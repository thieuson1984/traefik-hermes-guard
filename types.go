package traefik_hermes_guard

import (
	"net/http"
	"time"
)

// Verdict represents the decision on a request.
type Verdict string

const (
	VerdictAllow     Verdict = "allow"
	VerdictBlock     Verdict = "block"
	VerdictChallenge Verdict = "challenge"
)

// Mode defines the plugin operating mode.
type Mode string

const (
	ModeMonitor Mode = "monitor"
	ModeProtect Mode = "protect"
)

// LogLevel controls log verbosity.
type LogLevel string

const (
	LogDebug LogLevel = "debug"
	LogInfo  LogLevel = "info"
	LogWarn  LogLevel = "warn"
	LogError LogLevel = "error"
)

// DetectionResult holds the output of the Layer-1 fast-path analysis.
type DetectionResult struct {
	RiskScore       float64  `json:"risk_score"`
	MatchedPatterns []string `json:"matched_patterns"`
	Category        string   `json:"category,omitempty"`
	IsSuspicious    bool     `json:"is_suspicious"`
	Reason          string   `json:"reason,omitempty"`
	BodyBytes       []byte   `json:"-"`
}

// RiskScoring holds weights for fast-path detection, loaded from patterns.json.
type RiskScoring struct {
	URLMatchWeight       float64 `json:"url_match_weight"`
	BodyMatchWeight      float64 `json:"body_match_weight"`
	HeaderAnomalyWeight  float64 `json:"header_anomaly_weight"`
	MaliciousUAWeight    float64 `json:"malicious_ua_weight"`
	SuspiciousXFFWeight  float64 `json:"suspicious_xff_weight"`
	MethodOverrideWeight float64 `json:"method_override_weight"`
}

func defaultRiskScoring() RiskScoring {
	return RiskScoring{
		URLMatchWeight:       0.70,
		BodyMatchWeight:      0.35,
		HeaderAnomalyWeight:  0.05,
		MaliciousUAWeight:    0.60,
		SuspiciousXFFWeight:  0.20,
		MethodOverrideWeight: 0.20,
	}
}

// Cache is the interface for IP caching layer.
type Cache interface {
	IsBlocked(ip string) (bool, error)
	IsWhitelisted(ip string) (bool, error)
	BlockIP(ip string, ttl int) error
	UnblockIP(ip string) error
	UnwhitelistIP(ip string) error
	WhitelistIP(ip string) error
	RateLimitCheck(ip string, maxReqs, windowSec int) (bool, error)
	MarkChallenge(ip string, ttl int) error
	IsChallenged(ip string) bool
	EvalL1(ip string) (blocked bool, whitelisted bool, verdict *CacheEntry, err error)
	AuditLog(entry string) error
	Ping() error
	Close()
	Stats() map[string]int64
	BlockedCount() int
}

// CacheEntry represents a cached block decision.
type CacheEntry struct {
	Verdict   Verdict   `json:"verdict"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Detector is the interface for L1 attack pattern detection.
type Detector interface {
	Analyze(req *http.Request) *DetectionResult
}

// WebhookEvent payload for blocked IP notifications.
type WebhookEvent struct {
	Timestamp string  `json:"timestamp"`
	ClientIP  string  `json:"client_ip"`
	Host      string  `json:"host"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Reason    string  `json:"reason"`
	RiskScore float64 `json:"risk_score"`
	Verdict   string  `json:"verdict"`
}

// RespInspectResult holds data exfiltration detection results.
type RespInspectResult struct {
	MatchedPatterns []string `json:"matched_patterns,omitempty"`
	RiskScore       float64  `json:"risk_score"`
}
