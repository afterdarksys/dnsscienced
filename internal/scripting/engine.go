package scripting

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// Engine manages ThreatScript execution for DNS-level automation
type Engine struct {
	scripts     map[string]*Script
	mu          sync.RWMutex
	modules     map[string]*starlarkstruct.Module
	maxExecTime time.Duration
	maxMemory   int64
}

// Script represents a loaded ThreatScript
type Script struct {
	ID          string
	Name        string
	Code        string
	Compiled    starlark.Program
	Enabled     bool
	LastRun     time.Time
	RunCount    int
	ErrorCount  int
}

// ExecutionContext holds runtime information for script execution
type ExecutionContext struct {
	Query     *DNSQuery
	Variables map[string]interface{}
	StartTime time.Time
}

// DNSQuery represents a DNS query for script processing
type DNSQuery struct {
	Domain   string
	Type     string // A, AAAA, CNAME, MX, etc.
	ClientIP string
	ServerIP string
}

// ExecutionResult holds the result of script execution
type ExecutionResult struct {
	Success  bool
	Output   interface{}
	Error    error
	Duration time.Duration
	Actions  []string // Actions taken: "blocked", "redirected", etc.
}

// NewEngine creates a new ThreatScript engine for dnsscienced
func NewEngine() *Engine {
	e := &Engine{
		scripts:     make(map[string]*Script),
		modules:     make(map[string]*starlarkstruct.Module),
		maxExecTime: 5 * time.Second,
		maxMemory:   256 * 1024 * 1024, // 256MB
	}

	// Register DNS-specific modules
	e.registerModules()

	return e
}

// registerModules registers all ThreatScript modules
func (e *Engine) registerModules() {
	e.modules["dns"] = buildDNSModule()
	e.modules["threat"] = buildThreatModule()
	e.modules["firewall"] = buildFirewallModule()
	e.modules["log"] = buildLogModule()
	e.modules["notify"] = buildNotifyModule()
	e.modules["runtime"] = buildRuntimeModule()
}

// LoadScript loads and compiles a ThreatScript
func (e *Engine) LoadScript(id, name, code string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Create predeclared environment with all modules
	predeclared := starlark.StringDict{}
	for moduleName, module := range e.modules {
		predeclared[moduleName] = module
	}

	// Compile script
	_, prog, err := starlark.SourceProgram(name, code, predeclared.Has)
	if err != nil {
		return fmt.Errorf("compile error: %w", err)
	}

	script := &Script{
		ID:       id,
		Name:     name,
		Code:     code,
		Compiled: *prog,
		Enabled:  true,
	}

	e.scripts[id] = script
	return nil
}

// ExecuteOnQuery executes script in response to DNS query
func (e *Engine) ExecuteOnQuery(scriptID string, query *DNSQuery) (*ExecutionResult, error) {
	e.mu.RLock()
	script, ok := e.scripts[scriptID]
	e.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("script not found: %s", scriptID)
	}

	if !script.Enabled {
		return nil, fmt.Errorf("script disabled: %s", scriptID)
	}

	ctx := &ExecutionContext{
		Query:     query,
		Variables: make(map[string]interface{}),
		StartTime: time.Now(),
	}

	return e.execute(script, ctx)
}

// execute runs the script with timeout and memory limits
func (e *Engine) execute(script *Script, ctx *ExecutionContext) (*ExecutionResult, error) {
	result := &ExecutionResult{
		Actions: []string{},
	}

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(context.Background(), e.maxExecTime)
	defer cancel()

	// Create thread with context
	thread := &starlark.Thread{
		Name: script.Name,
	}

	// TODO: Implement memory limits via custom allocator

	// Prepare globals with modules
	globals := starlark.StringDict{}
	for name, module := range e.modules {
		globals[name] = module
	}

	// Add query context to runtime
	if ctx.Query != nil {
		globals["query"] = starlark.NewDict(4)
		globals["query"].(*starlark.Dict).SetKey(
			starlark.String("domain"),
			starlark.String(ctx.Query.Domain),
		)
		globals["query"].(*starlark.Dict).SetKey(
			starlark.String("type"),
			starlark.String(ctx.Query.Type),
		)
		globals["query"].(*starlark.Dict).SetKey(
			starlark.String("client_ip"),
			starlark.String(ctx.Query.ClientIP),
		)
		globals["query"].(*starlark.Dict).SetKey(
			starlark.String("server_ip"),
			starlark.String(ctx.Query.ServerIP),
		)
	}

	// Execute in goroutine with timeout
	done := make(chan struct{})
	var execErr error

	go func() {
		defer close(done)
		_, execErr = script.Compiled.Init(thread, globals)
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		if execErr != nil {
			result.Error = execErr
			result.Success = false
			script.ErrorCount++
		} else {
			result.Success = true
		}
	case <-execCtx.Done():
		result.Error = fmt.Errorf("script execution timeout")
		result.Success = false
		script.ErrorCount++
	}

	result.Duration = time.Since(ctx.StartTime)
	script.LastRun = time.Now()
	script.RunCount++

	return result, nil
}

// EnableScript enables a script
func (e *Engine) EnableScript(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	script, ok := e.scripts[id]
	if !ok {
		return fmt.Errorf("script not found: %s", id)
	}

	script.Enabled = true
	return nil
}

// DisableScript disables a script
func (e *Engine) DisableScript(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	script, ok := e.scripts[id]
	if !ok {
		return fmt.Errorf("script not found: %s", id)
	}

	script.Enabled = false
	return nil
}

// GetScript retrieves a script by ID
func (e *Engine) GetScript(id string) (*Script, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	script, ok := e.scripts[id]
	if !ok {
		return nil, fmt.Errorf("script not found: %s", id)
	}

	return script, nil
}

// ListScripts returns all loaded scripts
func (e *Engine) ListScripts() []*Script {
	e.mu.RLock()
	defer e.mu.RUnlock()

	scripts := make([]*Script, 0, len(e.scripts))
	for _, script := range e.scripts {
		scripts = append(scripts, script)
	}

	return scripts
}

// RemoveScript removes a script from the engine
func (e *Engine) RemoveScript(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.scripts[id]; !ok {
		return fmt.Errorf("script not found: %s", id)
	}

	delete(e.scripts, id)
	return nil
}
