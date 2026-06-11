package scripting

import (
	"testing"
	"time"
)

// TestExecute_RunawayScriptAborted proves the step budget terminates a runaway
// loop instead of leaking a goroutine that runs forever (finding F4).
func TestExecute_RunawayScriptAborted(t *testing.T) {
	e := NewEngine()
	// A top-level loop far larger than the step budget. Without SetMaxExecutionSteps
	// this would run until the process dies; with it, Init returns an error fast.
	// A module-level comprehension (top-level `for` statements are illegal in
	// Starlark) iterating far past the step budget. Init evaluates it directly.
	code := "result = [i for i in range(1000000000)]\n"
	if err := e.LoadScript("runaway", "runaway", code); err != nil {
		t.Fatalf("load: %v", err)
	}

	start := time.Now()
	res, err := e.ExecuteOnQuery("runaway", &DNSQuery{Domain: "x.com", Type: "A"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("execute returned err: %v", err)
	}
	if res.Success {
		t.Error("runaway script reported success; expected abort via step budget")
	}
	if elapsed > 4*time.Second {
		t.Errorf("runaway took %v; step budget should abort well under the 5s timeout", elapsed)
	}
}

// TestExecute_NormalScriptSucceeds confirms ordinary scripts still run cleanly.
func TestExecute_NormalScriptSucceeds(t *testing.T) {
	e := NewEngine()
	if err := e.LoadScript("ok", "ok", "log.info(\"hello\")\n"); err != nil {
		t.Fatalf("load: %v", err)
	}
	res, err := e.ExecuteOnQuery("ok", &DNSQuery{Domain: "x.com", Type: "A"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Success {
		t.Errorf("normal script failed: %v", res.Error)
	}
}
