package worker

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrPoolClosed indicates the pool has been shut down
	ErrPoolClosed = errors.New("worker pool closed")

	// ErrJobTimeout indicates a job timed out in queue
	ErrJobTimeout = errors.New("job timed out waiting in queue")

	// ErrQueueFull indicates the job queue is full
	ErrQueueFull = errors.New("job queue is full")

	// ErrResizeDownUnsupported indicates that this fixed pool cannot safely
	// remove already-running workers.
	ErrResizeDownUnsupported = errors.New("shrinking a running worker pool is not supported")
)

// Job represents a unit of work to be executed
type Job interface {
	Execute(ctx context.Context) error
}

// JobFunc is a function that implements Job interface
type JobFunc func(ctx context.Context) error

func (f JobFunc) Execute(ctx context.Context) error {
	return f(ctx)
}

// Config holds worker pool configuration
type Config struct {
	// Number of workers (default: runtime.NumCPU() * 4)
	Workers int

	// Job queue size (default: workers * 100)
	QueueSize int

	// Maximum time a job can wait in queue before rejection
	// 0 = no timeout (default)
	QueueTimeout time.Duration

	// Panic handler (called when worker panics)
	PanicHandler func(interface{})
}

// Pool is a bounded worker pool that prevents goroutine exhaustion
type Pool struct {
	workers      int
	queue        chan *jobWrapper
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	closed       atomic.Bool
	submitMu     sync.RWMutex
	queueSize    int
	queueTimeout time.Duration

	// Panic handling
	panicHandler func(interface{})

	// Statistics (atomic for lock-free access)
	jobsSubmitted atomic.Uint64
	jobsCompleted atomic.Uint64
	jobsRejected  atomic.Uint64
	jobsFailed    atomic.Uint64
	jobsTimedOut  atomic.Uint64
	totalLatency  atomic.Uint64 // Nanoseconds
	activeWorkers atomic.Int64
}

// jobWrapper wraps a job with context and result channel
type jobWrapper struct {
	job        Job
	ctx        context.Context
	resultCh   chan error
	submitTime time.Time
}

// NewPool creates a new worker pool
func NewPool(cfg Config) *Pool {
	if cfg.Workers == 0 {
		cfg.Workers = runtime.NumCPU() * 4
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = cfg.Workers * 100
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Pool{
		workers:      cfg.Workers,
		queue:        make(chan *jobWrapper, cfg.QueueSize),
		ctx:          ctx,
		cancel:       cancel,
		queueSize:    cfg.QueueSize,
		queueTimeout: cfg.QueueTimeout,
		panicHandler: cfg.PanicHandler,
	}

	// Start workers
	p.wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go p.worker(i)
	}

	return p
}

// worker is the main worker goroutine
func (p *Pool) worker(id int) {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return

		case wrapper, ok := <-p.queue:
			if !ok {
				return
			}

			p.executeJob(wrapper)
		}
	}
}

// executeJob executes a job with panic recovery
func (p *Pool) executeJob(wrapper *jobWrapper) {
	p.activeWorkers.Add(1)
	defer func() {
		if r := recover(); r != nil {
			p.totalLatency.Add(uint64(time.Since(wrapper.submitTime).Nanoseconds()))
			p.jobsFailed.Add(1)
			p.activeWorkers.Add(-1)

			// Job panicked - handle gracefully
			if p.panicHandler != nil {
				p.panicHandler(r)
			}

			// Send panic as error
			select {
			case wrapper.resultCh <- errors.New("job panicked"):
			default:
			}
		}
	}()

	// Execute job with context
	err := wrapper.job.Execute(wrapper.ctx)

	p.totalLatency.Add(uint64(time.Since(wrapper.submitTime).Nanoseconds()))
	if err != nil {
		p.jobsFailed.Add(1)
	} else {
		p.jobsCompleted.Add(1)
	}
	p.activeWorkers.Add(-1)

	// Send the result only after counters are visible to the caller.
	select {
	case wrapper.resultCh <- err:
	default:
		// Result channel was closed (timeout or caller gave up)
	}
}

// Submit submits a job to the pool
// Blocks until job is queued or context is canceled
func (p *Pool) Submit(ctx context.Context, job Job) error {
	p.submitMu.RLock()
	if p.closed.Load() {
		p.submitMu.RUnlock()
		return ErrPoolClosed
	}

	p.jobsSubmitted.Add(1)

	wrapper := &jobWrapper{
		job:        job,
		ctx:        ctx,
		resultCh:   make(chan error, 1),
		submitTime: time.Now(),
	}

	// Apply queue timeout if configured
	var timeoutCtx context.Context
	var cancel context.CancelFunc
	if p.queueTimeout > 0 {
		timeoutCtx, cancel = context.WithTimeout(ctx, p.queueTimeout)
		defer cancel()
	} else {
		timeoutCtx = ctx
	}

	// Try to queue the job
	select {
	case p.queue <- wrapper:
		p.submitMu.RUnlock()
		// Job queued successfully
		// Wait for result
		select {
		case err := <-wrapper.resultCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}

	case <-timeoutCtx.Done():
		p.submitMu.RUnlock()
		p.jobsTimedOut.Add(1)
		return ErrJobTimeout

	case <-p.ctx.Done():
		p.submitMu.RUnlock()
		return ErrPoolClosed
	}
}

// TrySubmit attempts to submit a job without blocking
// Returns ErrQueueFull if queue is full
func (p *Pool) TrySubmit(ctx context.Context, job Job) error {
	p.submitMu.RLock()
	if p.closed.Load() {
		p.submitMu.RUnlock()
		return ErrPoolClosed
	}

	p.jobsSubmitted.Add(1)

	wrapper := &jobWrapper{
		job:        job,
		ctx:        ctx,
		resultCh:   make(chan error, 1),
		submitTime: time.Now(),
	}

	// Non-blocking queue attempt
	select {
	case p.queue <- wrapper:
		p.submitMu.RUnlock()
		// Job queued successfully
		// Wait for result
		select {
		case err := <-wrapper.resultCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}

	default:
		p.submitMu.RUnlock()
		// Queue is full
		p.jobsRejected.Add(1)
		return ErrQueueFull
	}
}

// SubmitAsync submits a job asynchronously
// Does not wait for job completion
func (p *Pool) SubmitAsync(ctx context.Context, job Job) error {
	p.submitMu.RLock()
	if p.closed.Load() {
		p.submitMu.RUnlock()
		return ErrPoolClosed
	}

	p.jobsSubmitted.Add(1)

	wrapper := &jobWrapper{
		job:        job,
		ctx:        ctx,
		resultCh:   make(chan error, 1),
		submitTime: time.Now(),
	}

	// Try to queue (with timeout if configured)
	if p.queueTimeout > 0 {
		timeoutCtx, cancel := context.WithTimeout(ctx, p.queueTimeout)
		defer cancel()

		select {
		case p.queue <- wrapper:
			p.submitMu.RUnlock()
			return nil
		case <-timeoutCtx.Done():
			p.submitMu.RUnlock()
			p.jobsTimedOut.Add(1)
			return ErrJobTimeout
		case <-p.ctx.Done():
			p.submitMu.RUnlock()
			return ErrPoolClosed
		}
	}

	// No timeout - try non-blocking
	select {
	case p.queue <- wrapper:
		p.submitMu.RUnlock()
		return nil
	default:
		p.submitMu.RUnlock()
		p.jobsRejected.Add(1)
		return ErrQueueFull
	}
}

// Close gracefully shuts down the pool
// Waits for all in-flight jobs to complete
func (p *Pool) Close() error {
	p.submitMu.Lock()
	if p.closed.Swap(true) {
		p.submitMu.Unlock()
		return ErrPoolClosed
	}

	// Stop accepting new jobs
	close(p.queue)
	p.submitMu.Unlock()

	// Wait for workers to finish
	p.wg.Wait()

	// Cancel context
	p.cancel()

	return nil
}

// CloseTimeout closes the pool with a timeout
// Returns error if timeout is exceeded
func (p *Pool) CloseTimeout(timeout time.Duration) error {
	p.submitMu.Lock()
	if p.closed.Swap(true) {
		p.submitMu.Unlock()
		return ErrPoolClosed
	}

	close(p.queue)
	p.submitMu.Unlock()

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		p.cancel()
		return nil
	case <-time.After(timeout):
		p.cancel()
		return errors.New("shutdown timeout exceeded")
	}
}

// Stats returns pool statistics
type Stats struct {
	Workers      int
	BusyWorkers  int
	QueueSize    int
	QueueDepth   int
	Submitted    uint64
	Completed    uint64
	Rejected     uint64
	Failed       uint64
	TimedOut     uint64
	AvgLatencyNs uint64
	Utilization  float64 // % of workers busy
}

// GetStats returns current pool statistics
func (p *Pool) GetStats() Stats {
	p.submitMu.RLock()
	workers := p.workers
	p.submitMu.RUnlock()
	submitted := p.jobsSubmitted.Load()
	completed := p.jobsCompleted.Load()
	failed := p.jobsFailed.Load()
	rejected := p.jobsRejected.Load()
	timedOut := p.jobsTimedOut.Load()
	totalLatency := p.totalLatency.Load()

	var avgLatency uint64
	executed := completed + failed
	if executed > 0 {
		avgLatency = totalLatency / executed
	}

	active := p.activeWorkers.Load()
	var utilization float64
	if workers > 0 {
		utilization = float64(active) / float64(workers) * 100
	}

	return Stats{
		Workers:      workers,
		BusyWorkers:  int(active),
		QueueSize:    p.queueSize,
		QueueDepth:   len(p.queue),
		Submitted:    submitted,
		Completed:    completed,
		Rejected:     rejected,
		Failed:       failed,
		TimedOut:     timedOut,
		AvgLatencyNs: avgLatency,
		Utilization:  utilization,
	}
}

// Resize adjusts the number of workers (hot-resize)
// Experimental: may cause brief performance fluctuations
func (p *Pool) Resize(newSize int) error {
	p.submitMu.Lock()
	defer p.submitMu.Unlock()
	if p.closed.Load() {
		return ErrPoolClosed
	}

	if newSize < 1 {
		return errors.New("worker count must be at least 1")
	}

	currentSize := p.workers
	if newSize == currentSize {
		return nil
	}

	if newSize > currentSize {
		// Add workers
		diff := newSize - currentSize
		p.wg.Add(diff)
		for i := 0; i < diff; i++ {
			go p.worker(currentSize + i)
		}
	} else {
		return ErrResizeDownUnsupported
	}

	p.workers = newSize
	return nil
}

// QueueDepth returns current number of queued jobs
func (p *Pool) QueueDepth() int {
	return len(p.queue)
}

// IsHealthy returns true if pool is operating normally
func (p *Pool) IsHealthy() bool {
	if p.closed.Load() {
		return false
	}

	stats := p.GetStats()

	// Health checks:
	// 1. Queue not completely full
	// 2. Workers are processing (completed count increasing)
	// 3. Not too many failures

	queueUtilization := float64(stats.QueueDepth) / float64(stats.QueueSize)
	if queueUtilization > 0.95 {
		return false // Queue nearly full
	}

	if stats.Submitted > 100 && stats.Completed == 0 {
		return false // Jobs stuck
	}

	if stats.Failed > stats.Completed && stats.Completed > 0 {
		return false // More failures than successes
	}

	return true
}
