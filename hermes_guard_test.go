package traefik_hermes_guard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateConfig(t *testing.T) {
	cfg := CreateConfig()
	if cfg.Mode != "monitor" {
		t.Errorf("expected default mode 'monitor', got '%s'", cfg.Mode)
	}
	if cfg.MinRiskScore != 0.5 {
		t.Errorf("expected default minRiskScore 0.5, got %f", cfg.MinRiskScore)
	}
	if cfg.RateLimitReqs != 0 {
		t.Errorf("expected default rateLimitReqs 0, got %d", cfg.RateLimitReqs)
	}
	if cfg.PatternsWatchSec != 60 {
		t.Errorf("expected default patternsWatchSec 60, got %d", cfg.PatternsWatchSec)
	}
}

func TestDetectSQLInjection(t *testing.T) {
	patterns := []string{
		"(?i)(union.*select|select.*from|--[\\s]*$)",
		"(?i)(<script|javascript:)",
		"(?i)(\\.\\./|\\.\\.\\\\)",
	}
	d := newDetector(patterns, "", "", 1048576, newLogger(LogDebug))

	tests := []struct {
		name     string
		path     string
		wantRisk bool
	}{
		{"normal page", "/home", false},
		{"SQLi union select", "/products?id=1%20UNION%20SELECT%20password%20FROM%20users", true},
		{"XSS script", "/search?q=<script>alert(1)</script>", true},
		{"path traversal", "/download?file=../../../etc/passwd", true},
		{"clean API", "/api/v1/users", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com"+tc.path, nil)
			result := d.Analyze(req)
			if tc.wantRisk && !result.IsSuspicious {
				t.Errorf("expected suspicious for %s, risk=%f", tc.name, result.RiskScore)
			}
		})
	}
}

func TestDetectMaliciousUserAgent(t *testing.T) {
	d := newDetector(nil, "", "", 1048576, newLogger(LogDebug))
	tests := []struct {
		name     string
		ua       string
		wantRisk bool
	}{
		{"normal browser", "Mozilla/5.0 Chrome/120", false},
		{"sqlmap", "sqlmap/1.7.10#stable", true},
		{"nikto", "Nikto/2.1.6", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.Header.Set("User-Agent", tc.ua)
			result := d.Analyze(req)
			if tc.wantRisk && !result.IsSuspicious {
				t.Errorf("expected suspicious UA '%s'", tc.ua)
			}
		})
	}
}

func TestCIDRMatching(t *testing.T) {
	h := &handler{
		staticIPs: make(map[string]bool),
		logger:    newLogger(LogDebug),
	}
	h.addCIDR("10.0.0.0/8", true)
	h.addCIDR("127.0.0.1", true)
	if !h.ipInList("10.5.5.5") {
		t.Error("10.5.5.5 should match 10.0.0.0/8")
	}
	if !h.ipInList("127.0.0.1") {
		t.Error("127.0.0.1 should match exact")
	}
	if h.ipInList("8.8.8.8") {
		t.Error("8.8.8.8 should NOT match any whitelist")
	}
}

func TestHandlerMonitorMode(t *testing.T) {
	cfg := &Config{
		Mode:         string(ModeMonitor),
		MinRiskScore: 0.7,
		MaxBodySize:  1048576,
		LogLevel:     string(LogDebug),
		SuspiciousPatterns: []string{"(?i)(union.*select)"},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	ctx := context.Background()
	h, err := New(ctx, next, cfg, "test")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	req := httptest.NewRequest("GET", "http://example.com/hello", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandlerProtectMode(t *testing.T) {
	cfg := &Config{
		Mode:         string(ModeProtect),
		MinRiskScore: 0.3,
		MaxBodySize:  1048576,
		LogLevel:     string(LogDebug),
		SuspiciousPatterns: []string{"(?i)(union.*select)"},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	ctx := context.Background()
	h, err := New(ctx, next, cfg, "test")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	sqliReq := httptest.NewRequest("GET", "http://example.com/?id=1+UNION+SELECT", nil)
	sqliReq.RemoteAddr = "10.0.0.1:45678"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sqliReq)
	if rec.Code != http.StatusForbidden {
		t.Errorf("protect: expected 403, got %d", rec.Code)
	}
}

func TestDecoder(t *testing.T) {
	got := decodePercent("%2e%2e%2fetc%2fpasswd")
	if got != "../etc/passwd" {
		t.Errorf("decodePercent = %q, want %q", got, "../etc/passwd")
	}
}

func TestPatternReload(t *testing.T) {
	d := newDetector(nil, "", "config/collections", 1048576, newLogger(LogDebug))
	if len(d.patterns) == 0 {
		t.Error("expected patterns loaded from collections")
	}
	if err := d.Reload(); err != nil {
		t.Errorf("Reload() error: %v", err)
	}
}

func TestMaskEndpoint(t *testing.T) {
	if maskEndpoint("") != "(none)" {
		t.Error("empty should return (none)")
	}
	masked := maskEndpoint("http://user:pass@host:8080")
	if strings.Contains(masked, "user:pass") {
		t.Error("maskEndpoint should redact credentials")
	}
}

func TestDefaultRiskScoring(t *testing.T) {
	rs := defaultRiskScoring()
	if rs.URLMatchWeight != 0.70 {
		t.Errorf("expected 0.70, got %.2f", rs.URLMatchWeight)
	}
}

func TestAdminDashboard(t *testing.T) {
	cfg := &Config{
		Mode:         string(ModeMonitor),
		MaxBodySize:  1048576,
		AdminEnabled: true,
		LogLevel:     string(LogDebug),
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	ctx := context.Background()
	h, err := New(ctx, next, cfg, "test")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	req := httptest.NewRequest("GET", "http://example.com/.hermes-guard/admin", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("admin: expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Hermes Guard") {
		t.Error("admin page should contain title")
	}
}

func TestRateLimiting(t *testing.T) {
	cfg := &Config{
		Mode:             string(ModeMonitor),
		MaxBodySize:      1048576,
		RateLimitReqs:    2,
		RateLimitWindow:  60,
		RateLimitBlockTTL: 10,
		LogLevel:         string(LogDebug),
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	ctx := context.Background()
	h, err := New(ctx, next, cfg, "test")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.99.99.99:12345"

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if i < 2 && rec.Code != http.StatusOK {
			t.Errorf("req %d: expected 200, got %d", i, rec.Code)
		}
		if i == 2 && rec.Code != http.StatusForbidden {
			t.Errorf("req %d: expected 403 (rate limited), got %d", i, rec.Code)
		}
	}
}

func TestHealthCheck(t *testing.T) {
	cfg := &Config{Mode: string(ModeProtect), MaxBodySize: 1048576, AdminEnabled: true, LogLevel: string(LogDebug)}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	ctx := context.Background()
	h, _ := New(ctx, next, cfg, "test")
	req := httptest.NewRequest("GET", "http://example.com/.hermes-guard/health", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("health: expected 200, got %d", rec.Code)
	}
}

func TestAPIAuth(t *testing.T) {
	cfg := &Config{Mode: string(ModeProtect), MaxBodySize: 1048576, AdminSecret: "test", LogLevel: string(LogDebug)}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h, _ := New(context.Background(), next, cfg, "test")
	req := httptest.NewRequest("GET", "http://example.com/.hermes-guard/api/status?ip=1.2.3.4", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
	req2 := httptest.NewRequest("GET", "http://example.com/.hermes-guard/api/status?ip=1.2.3.4&secret=test", nil)
	req2.RemoteAddr = "127.0.0.1:12345"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec2.Code)
	}
}
