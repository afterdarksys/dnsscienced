package firewalld

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// StarlarkEngine executes Starlark-based DNS policy scripts.
//
// Each script is compiled once.  At query time, the script's on_query()
// function is called with a query struct.  The function sets its verdict
// by calling one of:
//
//	firewall.allow()
//	firewall.nxdomain(reason="...")
//	firewall.drop(reason="...")
//	firewall.rewrite(target="sink.example.", reason="...")
//	firewall.redirect(server="1.2.3.4:5353", reason="...")
//
// Example policy script:
//
//	def on_query(q, score):
//	    if score > 60 and q.type == "A":
//	        firewall.nxdomain(reason="moderate threat score")
//	    if q.name.endswith(".ru."):
//	        firewall.nxdomain(reason="geo block")
type StarlarkEngine struct {
	mu      sync.RWMutex
	scripts map[string]*compiledScript
	timeout time.Duration
	pool    *UpstreamPool
}

type compiledScript struct {
	id      string
	prog    *starlark.Program
	enabled bool
}

func newStarlarkEngine(timeout time.Duration) (*StarlarkEngine, error) {
	if timeout == 0 {
		timeout = 2 * time.Millisecond
	}
	return &StarlarkEngine{
		scripts: make(map[string]*compiledScript),
		timeout: timeout,
	}, nil
}

// LoadFile compiles and registers a Starlark policy script from path.
// The path is used as the script ID; loading the same path again replaces it.
func (se *StarlarkEngine) LoadFile(path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return se.Load(path, string(src))
}

// Load compiles and registers a Starlark policy script from src.
// id should be unique (typically the file path).
func (se *StarlarkEngine) Load(id, src string) error {
	predeclared := starlark.StringDict{
		"firewall": se.buildFirewallModule(),
	}

	_, prog, err := starlark.SourceProgram(id, src, predeclared.Has)
	if err != nil {
		return fmt.Errorf("compile %s: %w", id, err)
	}

	se.mu.Lock()
	se.scripts[id] = &compiledScript{id: id, prog: prog, enabled: true}
	se.mu.Unlock()
	return nil
}

// Remove unloads a script by ID.
func (se *StarlarkEngine) Remove(id string) {
	se.mu.Lock()
	delete(se.scripts, id)
	se.mu.Unlock()
}

// Run executes all enabled scripts against qctx.
// Returns the first non-ALLOW decision, or ALLOW if all scripts pass.
func (se *StarlarkEngine) Run(qctx *QueryContext, threatScore int) *Decision {
	se.mu.RLock()
	scripts := make([]*compiledScript, 0, len(se.scripts))
	for _, s := range se.scripts {
		if s.enabled {
			scripts = append(scripts, s)
		}
	}
	se.mu.RUnlock()

	for _, s := range scripts {
		d, err := se.runOne(s, qctx, threatScore)
		if err != nil {
			// Script error: log and continue to next.
			continue
		}
		if d.Verdict != VerdictAllow {
			d.RuleName = "starlark:" + s.id
			return d
		}
	}
	return allow()
}

// runOne executes a single compiled script and returns its decision.
func (se *StarlarkEngine) runOne(s *compiledScript, qctx *QueryContext, threatScore int) (*Decision, error) {
	// decisionSink is populated by the firewall module builtins.
	sink := &decisionSink{d: allow()}

	// Build the firewall module bound to this sink.
	fwModule := se.buildFirewallModuleWithSink(sink)

	predeclared := starlark.StringDict{
		"firewall": fwModule,
	}

	thread := &starlark.Thread{Name: s.id}

	// Initialise the module (runs top-level code, defines on_query).
	globals, err := s.prog.Init(thread, predeclared)
	if err != nil {
		return nil, fmt.Errorf("init %s: %w", s.id, err)
	}

	// Look for on_query function.
	onQuery, ok := globals["on_query"]
	if !ok {
		// Script has no on_query — treat as allow.
		return allow(), nil
	}

	fn, ok := onQuery.(starlark.Callable)
	if !ok {
		return nil, fmt.Errorf("%s: on_query is not callable", s.id)
	}

	// Build query struct.
	queryVal := buildQueryValue(qctx, threatScore)

	// Run with timeout.
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), se.timeout)
	defer cancel()

	go func() {
		_, err := starlark.Call(thread, fn, starlark.Tuple{queryVal, starlark.MakeInt(threatScore)}, nil)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("on_query in %s: %w", s.id, err)
		}
	case <-ctx.Done():
		thread.Cancel("timeout")
		return nil, fmt.Errorf("on_query in %s timed out", s.id)
	}

	return sink.d, nil
}

// decisionSink holds the decision set by firewall.* builtins.
type decisionSink struct {
	mu sync.Mutex
	d  *Decision
}

func (ds *decisionSink) set(d *Decision) {
	ds.mu.Lock()
	ds.d = d
	ds.mu.Unlock()
}

// buildFirewallModule builds the firewall.* Starlark module stub used during
// compilation (no real sink attached, used only for predeclared names).
func (se *StarlarkEngine) buildFirewallModule() *starlarkstruct.Module {
	return se.buildFirewallModuleWithSink(&decisionSink{d: allow()})
}

// buildFirewallModuleWithSink builds the firewall.* module wired to sink.
func (se *StarlarkEngine) buildFirewallModuleWithSink(sink *decisionSink) *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "firewall",
		Members: starlark.StringDict{
			"allow": starlark.NewBuiltin("firewall.allow", func(
				_ *starlark.Thread, _ *starlark.Builtin,
				args starlark.Tuple, kwargs []starlark.Tuple,
			) (starlark.Value, error) {
				sink.set(allow())
				return starlark.None, nil
			}),

			"nxdomain": starlark.NewBuiltin("firewall.nxdomain", func(
				_ *starlark.Thread, _ *starlark.Builtin,
				args starlark.Tuple, kwargs []starlark.Tuple,
			) (starlark.Value, error) {
				reason := "starlark policy"
				var reasonStr starlark.String
				if err := starlark.UnpackArgs("firewall.nxdomain", args, kwargs,
					"reason?", &reasonStr); err == nil && reasonStr != "" {
					reason = string(reasonStr)
				}
				sink.set(&Decision{Verdict: VerdictNXDomain, Reason: reason})
				return starlark.None, nil
			}),

			"drop": starlark.NewBuiltin("firewall.drop", func(
				_ *starlark.Thread, _ *starlark.Builtin,
				args starlark.Tuple, kwargs []starlark.Tuple,
			) (starlark.Value, error) {
				reason := "starlark policy"
				var reasonStr starlark.String
				if err := starlark.UnpackArgs("firewall.drop", args, kwargs,
					"reason?", &reasonStr); err == nil && reasonStr != "" {
					reason = string(reasonStr)
				}
				sink.set(&Decision{Verdict: VerdictDrop, Reason: reason})
				return starlark.None, nil
			}),

			"rewrite": starlark.NewBuiltin("firewall.rewrite", func(
				_ *starlark.Thread, _ *starlark.Builtin,
				args starlark.Tuple, kwargs []starlark.Tuple,
			) (starlark.Value, error) {
				var target, reason starlark.String
				if err := starlark.UnpackArgs("firewall.rewrite", args, kwargs,
					"target", &target, "reason?", &reason); err != nil {
					return nil, err
				}
				if string(target) == "" {
					return nil, fmt.Errorf("firewall.rewrite: target must not be empty")
				}
				r := "starlark policy"
				if string(reason) != "" {
					r = string(reason)
				}
				sink.set(&Decision{Verdict: VerdictRewrite, Target: string(target), Reason: r})
				return starlark.None, nil
			}),

			"redirect": starlark.NewBuiltin("firewall.redirect", func(
				_ *starlark.Thread, _ *starlark.Builtin,
				args starlark.Tuple, kwargs []starlark.Tuple,
			) (starlark.Value, error) {
				// D-02: hard error if caller passes server= kwarg.
				// This check must run before UnpackArgs so "server" is not silently ignored.
				for _, kv := range kwargs {
					if string(kv[0].(starlark.String)) == "server" {
						return nil, fmt.Errorf("firewall.redirect: server arg removed — configure upstreams in firewall.redirect.upstreams")
					}
				}
				var reason starlark.String
				if err := starlark.UnpackArgs("firewall.redirect", args, kwargs,
					"reason?", &reason); err != nil {
					return nil, err
				}
				// D-04: pool.Next() selects the upstream target.
				server, err := se.pool.Next()
				if err != nil {
					return nil, fmt.Errorf("firewall.redirect: %w", err)
				}
				r := "starlark policy"
				if string(reason) != "" {
					r = string(reason)
				}
				sink.set(&Decision{Verdict: VerdictRedirect, Server: server, Reason: r})
				return starlark.None, nil
			}),
		},
	}
}

// buildQueryValue builds the Starlark dict passed to on_query(q, score).
func buildQueryValue(qctx *QueryContext, threatScore int) *starlark.Dict {
	d := starlark.NewDict(6)
	_ = d.SetKey(starlark.String("name"), starlark.String(qctx.Name))
	_ = d.SetKey(starlark.String("type"), starlark.String(dnsTypeName(qctx.Qtype)))
	_ = d.SetKey(starlark.String("type_num"), starlark.MakeInt(int(qctx.Qtype)))
	_ = d.SetKey(starlark.String("client_ip"), starlark.String(qctx.ClientIP.String()))
	_ = d.SetKey(starlark.String("customer_id"), starlark.String(qctx.CustomerID))
	_ = d.SetKey(starlark.String("threat_score"), starlark.MakeInt(threatScore))
	return d
}

func dnsTypeName(t uint16) string {
	if name, ok := dnsTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}

var dnsTypeNames = map[uint16]string{
	1:  "A",
	2:  "NS",
	5:  "CNAME",
	6:  "SOA",
	12: "PTR",
	15: "MX",
	16: "TXT",
	28: "AAAA",
	33: "SRV",
	43: "DS",
	46: "RRSIG",
	47: "NSEC",
	48: "DNSKEY",
	50: "NSEC3",
	51: "NSEC3PARAM",
	52: "TLSA",
	99: "SPF",
	255: "ANY",
}
