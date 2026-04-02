package health

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Status represents the health status of the server
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
)

// Check represents a single health check
type Check struct {
	Name    string
	Status  Status
	Message string
	LastRun time.Time
}

// Health manages health checks for the DNS server
type Health struct {
	mu sync.RWMutex

	// Server status
	status atomic.Value // Status

	// Startup time
	startTime time.Time

	// Last query time (for liveness check)
	lastQuery atomic.Value // time.Time

	// Component health
	cacheHealthy       atomic.Bool
	resolverHealthy    atomic.Bool
	listenersHealthy   atomic.Bool
	zonesLoaded        atomic.Int32

	// Checks
	checks map[string]*Check
}

// New creates a new Health instance
func New() *Health {
	h := &Health{
		startTime: time.Now(),
		checks:    make(map[string]*Check),
	}

	// Initialize status
	h.status.Store(StatusHealthy)
	h.lastQuery.Store(time.Now())

	// Set defaults
	h.cacheHealthy.Store(true)
	h.resolverHealthy.Store(true)
	h.listenersHealthy.Store(true)

	return h
}

// SetStatus sets the overall health status
func (h *Health) SetStatus(status Status) {
	h.status.Store(status)
}

// GetStatus returns the current health status
func (h *Health) GetStatus() Status {
	return h.status.Load().(Status)
}

// RecordQuery records that a query was processed
func (h *Health) RecordQuery() {
	h.lastQuery.Store(time.Now())
}

// SetCacheHealth sets the cache health status
func (h *Health) SetCacheHealth(healthy bool) {
	h.cacheHealthy.Store(healthy)
}

// SetResolverHealth sets the resolver health status
func (h *Health) SetResolverHealth(healthy bool) {
	h.resolverHealthy.Store(healthy)
}

// SetListenersHealth sets the listeners health status
func (h *Health) SetListenersHealth(healthy bool) {
	h.listenersHealthy.Store(healthy)
}

// SetZoneCount sets the number of loaded zones
func (h *Health) SetZoneCount(count int) {
	h.zonesLoaded.Store(int32(count))
}

// IsHealthy returns true if the server is healthy
func (h *Health) IsHealthy() bool {
	// Check if all components are healthy
	if !h.cacheHealthy.Load() {
		return false
	}
	if !h.resolverHealthy.Load() {
		return false
	}
	if !h.listenersHealthy.Load() {
		return false
	}

	// Check if we've received queries recently (liveness)
	lastQuery := h.lastQuery.Load().(time.Time)
	if time.Since(lastQuery) > 60*time.Second {
		// No queries in 60 seconds - might be unhealthy
		// But don't fail health check immediately
		return h.GetStatus() != StatusUnhealthy
	}

	return h.GetStatus() == StatusHealthy
}

// IsReady returns true if the server is ready to serve traffic
func (h *Health) IsReady() bool {
	// Server is ready if:
	// 1. All listeners are active
	// 2. At least some time has passed since startup (initialization complete)
	// 3. Cache is operational

	if !h.listenersHealthy.Load() {
		return false
	}

	if time.Since(h.startTime) < 2*time.Second {
		// Still initializing
		return false
	}

	if !h.cacheHealthy.Load() {
		return false
	}

	return true
}

// HealthResponse is the JSON response for health checks
type HealthResponse struct {
	Status       Status        `json:"status"`
	Timestamp    time.Time     `json:"timestamp"`
	Uptime       float64       `json:"uptime_seconds"`
	LastQuery    time.Time     `json:"last_query"`
	ZoneCount    int32         `json:"zone_count"`
	Components   ComponentHealth `json:"components"`
	Checks       []Check       `json:"checks,omitempty"`
}

// ComponentHealth represents the health of individual components
type ComponentHealth struct {
	Cache     bool `json:"cache"`
	Resolver  bool `json:"resolver"`
	Listeners bool `json:"listeners"`
}

// HealthHandler returns an HTTP handler for /health endpoint
func (h *Health) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		isHealthy := h.IsHealthy()

		resp := HealthResponse{
			Status:    h.GetStatus(),
			Timestamp: time.Now(),
			Uptime:    time.Since(h.startTime).Seconds(),
			LastQuery: h.lastQuery.Load().(time.Time),
			ZoneCount: h.zonesLoaded.Load(),
			Components: ComponentHealth{
				Cache:     h.cacheHealthy.Load(),
				Resolver:  h.resolverHealthy.Load(),
				Listeners: h.listenersHealthy.Load(),
			},
		}

		// Add detailed checks if requested
		if r.URL.Query().Get("detailed") == "true" {
			h.mu.RLock()
			for _, check := range h.checks {
				resp.Checks = append(resp.Checks, *check)
			}
			h.mu.RUnlock()
		}

		w.Header().Set("Content-Type", "application/json")

		if !isHealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		json.NewEncoder(w).Encode(resp)
	}
}

// ReadyHandler returns an HTTP handler for /ready endpoint
func (h *Health) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		isReady := h.IsReady()

		resp := map[string]interface{}{
			"ready":     isReady,
			"timestamp": time.Now(),
			"uptime":    time.Since(h.startTime).Seconds(),
		}

		w.Header().Set("Content-Type", "application/json")

		if !isReady {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		json.NewEncoder(w).Encode(resp)
	}
}

// LiveHandler returns an HTTP handler for /live endpoint (simple liveness)
func (h *Health) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Liveness is very simple - just check if process is running
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK\n"))
	}
}

// ServeHTTP starts the health check HTTP server
func ServeHTTP(h *Health, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.HealthHandler())
	mux.HandleFunc("/ready", h.ReadyHandler())
	mux.HandleFunc("/live", h.LiveHandler())

	return http.ListenAndServe(addr, mux)
}
