package worker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewPool(t *testing.T) {
	cfg := Config{
		Workers:   4,
		QueueSize: 100,
	}

	pool := NewPool(cfg)
	defer pool.Close()

	if pool.workers != 4 {
		t.Errorf("workers = %d, want 4", pool.workers)
	}

	if pool.queueSize != 100 {
		t.Errorf("queueSize = %d, want 100", pool.queueSize)
	}
}

func TestNewPool_Defaults(t *testing.T) {
	cfg := Config{} // No configuration

	pool := NewPool(cfg)
	defer pool.Close()

	// Should use defaults
	if pool.workers == 0 {
		t.Error("should have default workers")
	}

	if pool.queueSize == 0 {
		t.Error("should have default queue size")
	}
}

func TestSubmit_Success(t *testing.T) {
	pool := NewPool(Config{Workers: 2, QueueSize: 10})
	defer pool.Close()

	executed := false
	job := JobFunc(func(ctx context.Context) error {
		executed = true
		return nil
	})

	err := pool.Submit(context.Background(), job)
	if err != nil {
		t.Fatalf("Submit() error: %v", err)
	}

	// Give worker time to execute
	time.Sleep(10 * time.Millisecond)

	if !executed {
		t.Error("job was not executed")
	}

	stats := pool.GetStats()
	if stats.Completed != 1 {
		t.Errorf("completed = %d, want 1", stats.Completed)
	}
}

func TestSubmit_JobError(t *testing.T) {
	pool := NewPool(Config{Workers: 2, QueueSize: 10})
	defer pool.Close()

	expectedErr := errors.New("job failed")
	job := JobFunc(func(ctx context.Context) error {
		return expectedErr
	})

	err := pool.Submit(context.Background(), job)
	if err != expectedErr {
		t.Errorf("Submit() error = %v, want %v", err, expectedErr)
	}

	stats := pool.GetStats()
	if stats.Failed != 1 {
		t.Errorf("failed = %d, want 1", stats.Failed)
	}
}

func TestSubmit_ContextCanceled(t *testing.T) {
	pool := NewPool(Config{Workers: 2, QueueSize: 10})
	defer pool.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	job := JobFunc(func(ctx context.Context) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	})

	err := pool.Submit(ctx, job)
	// Can be either context.Canceled or ErrJobTimeout depending on timing
	if err != context.Canceled && err != ErrJobTimeout {
		t.Errorf("Submit() error = %v, want context.Canceled or ErrJobTimeout", err)
	}
}

func TestSubmit_Panic(t *testing.T) {
	panicCaught := false
	pool := NewPool(Config{
		Workers:   2,
		QueueSize: 10,
		PanicHandler: func(r interface{}) {
			panicCaught = true
		},
	})
	defer pool.Close()

	job := JobFunc(func(ctx context.Context) error {
		panic("test panic")
	})

	err := pool.Submit(context.Background(), job)
	if err == nil {
		t.Error("Submit() should return error when job panics")
	}

	time.Sleep(10 * time.Millisecond)

	if !panicCaught {
		t.Error("panic handler was not called")
	}

	stats := pool.GetStats()
	if stats.Failed != 1 {
		t.Errorf("failed = %d, want 1", stats.Failed)
	}
}

func TestTrySubmit_QueueFull(t *testing.T) {
	pool := NewPool(Config{Workers: 1, QueueSize: 1})
	defer pool.Close()

	// Block the worker with a long-running job
	blocker := JobFunc(func(ctx context.Context) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	pool.SubmitAsync(context.Background(), blocker)

	// Fill the queue
	filler := JobFunc(func(ctx context.Context) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	pool.SubmitAsync(context.Background(), filler)

	// Next job should fail with queue full
	job := JobFunc(func(ctx context.Context) error {
		return nil
	})

	err := pool.TrySubmit(context.Background(), job)
	if err != ErrQueueFull {
		t.Errorf("TrySubmit() error = %v, want ErrQueueFull", err)
	}

	stats := pool.GetStats()
	if stats.Rejected == 0 {
		t.Error("rejected count should be non-zero")
	}
}

func TestSubmitAsync(t *testing.T) {
	pool := NewPool(Config{Workers: 2, QueueSize: 10})
	defer pool.Close()

	var executed atomic.Bool
	job := JobFunc(func(ctx context.Context) error {
		executed.Store(true)
		return nil
	})

	err := pool.SubmitAsync(context.Background(), job)
	if err != nil {
		t.Fatalf("SubmitAsync() error: %v", err)
	}

	// Wait for execution
	time.Sleep(20 * time.Millisecond)

	if !executed.Load() {
		t.Error("async job was not executed")
	}
}

func TestClose(t *testing.T) {
	pool := NewPool(Config{Workers: 2, QueueSize: 10})

	// Submit some jobs
	for i := 0; i < 5; i++ {
		pool.SubmitAsync(context.Background(), JobFunc(func(ctx context.Context) error {
			time.Sleep(10 * time.Millisecond)
			return nil
		}))
	}

	// Close should wait for jobs to complete
	err := pool.Close()
	if err != nil {
		t.Errorf("Close() error: %v", err)
	}

	// Pool should be closed
	err = pool.Submit(context.Background(), JobFunc(func(ctx context.Context) error {
		return nil
	}))
	if err != ErrPoolClosed {
		t.Errorf("Submit after close error = %v, want ErrPoolClosed", err)
	}
}

func TestCloseTimeout(t *testing.T) {
	pool := NewPool(Config{Workers: 1, QueueSize: 10})

	// Submit a long-running job
	pool.SubmitAsync(context.Background(), JobFunc(func(ctx context.Context) error {
		time.Sleep(1 * time.Second)
		return nil
	}))

	// Close with short timeout should timeout
	err := pool.CloseTimeout(10 * time.Millisecond)
	if err == nil {
		t.Error("CloseTimeout() should return error on timeout")
	}
}

func TestConcurrency(t *testing.T) {
	pool := NewPool(Config{Workers: 4, QueueSize: 100})
	defer pool.Close()

	const jobs = 100
	var completed atomic.Uint64

	var wg sync.WaitGroup
	wg.Add(jobs)

	// Submit jobs concurrently
	for i := 0; i < jobs; i++ {
		go func() {
			defer wg.Done()

			job := JobFunc(func(ctx context.Context) error {
				// Simulate work
				time.Sleep(time.Millisecond)
				completed.Add(1)
				return nil
			})

			err := pool.Submit(context.Background(), job)
			if err != nil {
				t.Errorf("Submit() error: %v", err)
			}
		}()
	}

	wg.Wait()

	if completed.Load() != jobs {
		t.Errorf("completed = %d, want %d", completed.Load(), jobs)
	}

	stats := pool.GetStats()
	if stats.Submitted != jobs {
		t.Errorf("submitted = %d, want %d", stats.Submitted, jobs)
	}
	if stats.Completed != jobs {
		t.Errorf("completed = %d, want %d", stats.Completed, jobs)
	}
}

func TestStats(t *testing.T) {
	pool := NewPool(Config{Workers: 2, QueueSize: 10})
	defer pool.Close()

	// Submit successful job
	pool.Submit(context.Background(), JobFunc(func(ctx context.Context) error {
		return nil
	}))

	// Submit failing job
	pool.Submit(context.Background(), JobFunc(func(ctx context.Context) error {
		return errors.New("fail")
	}))

	time.Sleep(20 * time.Millisecond)

	stats := pool.GetStats()
	if stats.Submitted != 2 {
		t.Errorf("submitted = %d, want 2", stats.Submitted)
	}
	if stats.Completed != 1 {
		t.Errorf("completed = %d, want 1", stats.Completed)
	}
	if stats.Failed != 1 {
		t.Errorf("failed = %d, want 1", stats.Failed)
	}
}

func TestQueueTimeout(t *testing.T) {
	pool := NewPool(Config{
		Workers:      1,
		QueueSize:    1,
		QueueTimeout: 50 * time.Millisecond,
	})
	defer pool.Close()

	// Block worker
	pool.SubmitAsync(context.Background(), JobFunc(func(ctx context.Context) error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}))

	// Fill queue
	pool.SubmitAsync(context.Background(), JobFunc(func(ctx context.Context) error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}))

	// This should timeout
	err := pool.Submit(context.Background(), JobFunc(func(ctx context.Context) error {
		return nil
	}))

	if err != ErrJobTimeout {
		t.Errorf("Submit() error = %v, want ErrJobTimeout", err)
	}

	stats := pool.GetStats()
	if stats.TimedOut == 0 {
		t.Error("timed out count should be non-zero")
	}
}

func TestResize(t *testing.T) {
	pool := NewPool(Config{Workers: 2, QueueSize: 100})
	defer pool.Close()

	// Resize up
	err := pool.Resize(4)
	if err != nil {
		t.Errorf("Resize(4) error: %v", err)
	}

	if pool.workers != 4 {
		t.Errorf("workers = %d, want 4", pool.workers)
	}

	// Submit jobs to verify new workers are active
	const jobs = 10
	for i := 0; i < jobs; i++ {
		pool.SubmitAsync(context.Background(), JobFunc(func(ctx context.Context) error {
			time.Sleep(time.Millisecond)
			return nil
		}))
	}

	time.Sleep(50 * time.Millisecond)

	stats := pool.GetStats()
	if stats.Completed != jobs {
		t.Errorf("completed = %d, want %d", stats.Completed, jobs)
	}
}

func TestResizeDownReturnsUnsupported(t *testing.T) {
	pool := NewPool(Config{Workers: 2, QueueSize: 10})
	defer pool.Close()

	if err := pool.Resize(1); !errors.Is(err, ErrResizeDownUnsupported) {
		t.Fatalf("Resize(1) error = %v, want ErrResizeDownUnsupported", err)
	}
	if stats := pool.GetStats(); stats.Workers != 2 {
		t.Fatalf("workers = %d after rejected shrink, want 2", stats.Workers)
	}
}

func TestStatsReportActiveWorkers(t *testing.T) {
	pool := NewPool(Config{Workers: 1, QueueSize: 1})
	defer pool.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	if err := pool.SubmitAsync(context.Background(), JobFunc(func(context.Context) error {
		close(started)
		<-release
		return nil
	})); err != nil {
		t.Fatalf("SubmitAsync: %v", err)
	}
	<-started

	stats := pool.GetStats()
	if stats.BusyWorkers != 1 || stats.Utilization != 100 {
		t.Fatalf("busy=%d utilization=%.1f, want 1 and 100", stats.BusyWorkers, stats.Utilization)
	}
	close(release)
}

func TestConcurrentSubmitAndCloseDoesNotPanic(t *testing.T) {
	for range 20 {
		pool := NewPool(Config{Workers: 2, QueueSize: 10})
		var wg sync.WaitGroup
		for range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = pool.SubmitAsync(context.Background(), JobFunc(func(context.Context) error {
					return nil
				}))
			}()
		}
		_ = pool.Close()
		wg.Wait()
	}
}

func TestIsHealthy(t *testing.T) {
	pool := NewPool(Config{Workers: 2, QueueSize: 10})
	defer pool.Close()

	if !pool.IsHealthy() {
		t.Error("new pool should be healthy")
	}

	// Submit some successful jobs
	for i := 0; i < 5; i++ {
		pool.SubmitAsync(context.Background(), JobFunc(func(ctx context.Context) error {
			return nil
		}))
	}

	time.Sleep(20 * time.Millisecond)

	if !pool.IsHealthy() {
		t.Error("pool with completed jobs should be healthy")
	}

	// Close pool
	pool.Close()

	if pool.IsHealthy() {
		t.Error("closed pool should not be healthy")
	}
}

func TestQueueDepth(t *testing.T) {
	pool := NewPool(Config{Workers: 1, QueueSize: 100})
	defer pool.Close()

	// Block worker
	pool.SubmitAsync(context.Background(), JobFunc(func(ctx context.Context) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	}))

	// Queue up some jobs
	for i := 0; i < 10; i++ {
		pool.SubmitAsync(context.Background(), JobFunc(func(ctx context.Context) error {
			return nil
		}))
	}

	depth := pool.QueueDepth()
	if depth == 0 {
		t.Error("queue depth should be non-zero")
	}
	if depth > 11 {
		t.Errorf("queue depth = %d, seems too high", depth)
	}
}

// Benchmark worker pool overhead
func BenchmarkSubmit(b *testing.B) {
	pool := NewPool(Config{Workers: 4, QueueSize: 1000})
	defer pool.Close()

	job := JobFunc(func(ctx context.Context) error {
		return nil
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Submit(context.Background(), job)
	}
}

// Benchmark async submission
func BenchmarkSubmitAsync(b *testing.B) {
	pool := NewPool(Config{Workers: 4, QueueSize: 1000})
	defer pool.Close()

	job := JobFunc(func(ctx context.Context) error {
		return nil
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.SubmitAsync(context.Background(), job)
	}
}

// Benchmark concurrent submissions
func BenchmarkSubmitConcurrent(b *testing.B) {
	pool := NewPool(Config{Workers: 4, QueueSize: 10000})
	defer pool.Close()

	job := JobFunc(func(ctx context.Context) error {
		return nil
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.SubmitAsync(context.Background(), job)
		}
	})
}
