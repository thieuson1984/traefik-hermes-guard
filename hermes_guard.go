package traefik_hermes_guard

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config holds all plugin configuration.
type Config struct {
	HermesEndpoint        string   `json:"hermesEndpoint"`
	HermesToken           string   `json:"hermesToken,omitempty"`
	HermesTLSInsecure     bool     `json:"hermesTLSInsecure,omitempty"`
	HermesTLSCAFile       string   `json:"hermesTLSCAFile,omitempty"`
	HermesRetryEnabled    bool     `json:"hermesRetryEnabled,omitempty"`
	HermesRetryInterval   int      `json:"hermesRetryInterval,omitempty"`
	HermesBlockWebhookURL    string   `json:"hermesBlockWebhookURL,omitempty"`
	HermesBlockWebhookSecret string   `json:"hermesBlockWebhookSecret,omitempty"`
	HermesAnalyzeURL         string   `json:"hermesAnalyzeURL,omitempty"`
	AdminSecret              string   `json:"adminSecret,omitempty"`
	RedisAddr             string   `json:"redisAddr"`
	RedisPassword         string   `json:"redisPassword,omitempty"`
	RedisDB               int      `json:"redisDB,omitempty"`
	Mode                  string   `json:"mode,omitempty"`
	LogLevel              string   `json:"logLevel,omitempty"`
	MinRiskScore          float64  `json:"minRiskScore,omitempty"`
	CacheTTL              int      `json:"cacheTTL,omitempty"`
	MaxBodySize           int64    `json:"maxBodySize,omitempty"`
	RateLimitReqs         int      `json:"rateLimitReqs,omitempty"`
	RateLimitWindow       int      `json:"rateLimitWindow,omitempty"`
	RateLimitBlockTTL     int      `json:"rateLimitBlockTTL,omitempty"`
	PatternsFile          string   `json:"patternsFile,omitempty"`
	CollectionsDir        string   `json:"collectionsDir,omitempty"`
	ProfileFile           string   `json:"profileFile,omitempty"`
	PatternsWatchSec      int      `json:"patternsWatchSec,omitempty"`
	BanPageFile           string   `json:"banPageFile,omitempty"`
	CaptchaPageFile       string   `json:"captchaPageFile,omitempty"`
	TurnstileSiteKey      string   `json:"turnstileSiteKey,omitempty"`
	TurnstileSecretKey    string   `json:"turnstileSecretKey,omitempty"`
	TrustCFHeaders        bool     `json:"trustCFHeaders,omitempty"`
	TrustedProxies        []string `json:"trustedProxies,omitempty"`
	SuspiciousPatterns    []string `json:"suspiciousPatterns,omitempty"`
	IPWhitelist           []string `json:"ipWhitelist,omitempty"`
	IPBlacklist           []string `json:"ipBlacklist,omitempty"`
	ChallengeURL          string   `json:"challengeURL,omitempty"`
	WebhookURL            string   `json:"webhookURL,omitempty"`
	AdminEnabled          bool     `json:"adminEnabled,omitempty"`
	GeoIPDBFile           string   `json:"geoipDBFile,omitempty"`
	BlockCountries        []string `json:"blockCountries,omitempty"`
	ChallengeCountries    []string `json:"challengeCountries,omitempty"`
	InspectResponses      bool     `json:"inspectResponses,omitempty"`
	SilentStartUp         bool     `json:"silentStartUp,omitempty"`
	AllowLocalRequests    bool     `json:"allowLocalRequests,omitempty"`
	BlackListMode         bool     `json:"blackListMode,omitempty"`
	AddCountryHeader      bool     `json:"addCountryHeader,omitempty"`
	HTTPStatusCodeDenied  int      `json:"httpStatusCodeDenied,omitempty"`
	RedirectURLIfDenied   string   `json:"redirectUrlIfDenied,omitempty"`
	ExcludedPathPatterns  []string `json:"excludedPathPatterns,omitempty"`
	FallbackWhenError     bool     `json:"fallbackWhenError,omitempty"`

	// Feature: Rate limit by path
	RateLimitPaths        []RateLimitPath `json:"rateLimitPaths,omitempty"`
	// Feature: Honeypot mode
	HoneypotPaths         []string `json:"honeypotPaths,omitempty"`
	// Feature: IP reputation
	AbuseIPDBKey          string   `json:"abuseIPDBKey,omitempty"`
	AbuseIPDBThreshold    int      `json:"abuseIPDBThreshold,omitempty"`
	// Feature: Multi-tenancy
	HostProfiles          []HostProfile `json:"hostProfiles,omitempty"`
	// Feature: GeoIP auto-update
	GeoIPUpdateURL        string   `json:"geoipUpdateURL,omitempty"`
	GeoIPUpdateIntervalH  int      `json:"geoipUpdateIntervalH,omitempty"`
	HermesFeedbackEnabled  bool     `json:"hermesFeedbackEnabled,omitempty"`
	JA3BlockList           []string `json:"ja3BlockList,omitempty"`

	// Feature: Redis TLS
	RedisTLSEnabled        bool     `json:"redisTLSEnabled,omitempty"`
	RedisTLSSkipVerify     bool     `json:"redisTLSSkipVerify,omitempty"`

	// Feature: Scheduled blocking
	ScheduledRules         []ScheduledRule `json:"scheduledRules,omitempty"`
}

type ScheduledRule struct {
	CronExpr  string   `json:"cronExpr"`  // HH:MM-HH:MM format
	Action    string   `json:"action"`    // block | captcha
	Paths     []string `json:"paths,omitempty"`
	Countries []string `json:"countries,omitempty"`
}

type RateLimitPath struct {
	Path    string `json:"path"`    // regex pattern
	MaxReqs int    `json:"maxReqs"`
	Window  int    `json:"window"`  // seconds
}

type HostProfile struct {
	Host          string   `json:"host"`          // domain
	Mode          string   `json:"mode,omitempty"`
	MinRiskScore  float64  `json:"minRiskScore,omitempty"`
	BlockCountries []string `json:"blockCountries,omitempty"`
	Collections   []string `json:"collections,omitempty"` // override which collections
}

func CreateConfig() *Config {
	return &Config{
		Mode:                string(ModeMonitor),
		MinRiskScore:        0.5,
		CacheTTL:            3600,
		MaxBodySize:         1048576,
		LogLevel:            string(LogInfo),
		RateLimitReqs:       0,
		RateLimitWindow:     60,
		RateLimitBlockTTL:   300,
		HermesRetryInterval: 30,
		PatternsWatchSec:    60,
		AllowLocalRequests:  false,
		HTTPStatusCodeDenied: 403,
		FallbackWhenError:   true,
	}
}

func resolveConfig(cfg *Config) {
	if v := os.Getenv("HG_HERMES_ENDPOINT"); v != "" {
		cfg.HermesEndpoint = v
	}
	if v := os.Getenv("HG_HERMES_TOKEN"); v != "" {
		cfg.HermesToken = v
	}
	if v := os.Getenv("HG_REDIS_ADDR"); v != "" {
		cfg.RedisAddr = v
	}
	if v := os.Getenv("HG_REDIS_PASSWORD"); v != "" {
		cfg.RedisPassword = v
	}
	if v := os.Getenv("HG_REDIS_DB"); v != "" {
		if n, _ := strconv.Atoi(v); cfg.RedisDB == 0 {
			cfg.RedisDB = n
		}
	}
	if v := os.Getenv("HG_MODE"); v != "" && cfg.Mode == "" {
		cfg.Mode = v
	}
	if v := os.Getenv("HG_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("HG_MIN_RISK_SCORE"); v != "" {
		if f, _ := strconv.ParseFloat(v, 64); cfg.MinRiskScore == 0 {
			cfg.MinRiskScore = f
		}
	}
	if v := os.Getenv("HG_CACHE_TTL"); v != "" {
		if n, _ := strconv.Atoi(v); cfg.CacheTTL == 0 {
			cfg.CacheTTL = n
		}
	}
	if v := os.Getenv("HG_MAX_BODY_SIZE"); v != "" {
		if n, _ := strconv.ParseInt(v, 10, 64); cfg.MaxBodySize == 0 {
			cfg.MaxBodySize = n
		}
	}
	if v := os.Getenv("HG_CHALLENGE_URL"); v != "" {
		cfg.ChallengeURL = v
	}
	if v := os.Getenv("HG_TURNSTILE_SITE_KEY"); v != "" {
		cfg.TurnstileSiteKey = v
	}
	if v := os.Getenv("HG_TURNSTILE_SECRET_KEY"); v != "" {
		cfg.TurnstileSecretKey = v
	}
	if v := os.Getenv("HG_WEBHOOK_URL"); v != "" {
		cfg.WebhookURL = v
	}
	if v := os.Getenv("HG_HERMES_BLOCK_WEBHOOK_SECRET"); v != "" {
		cfg.HermesBlockWebhookSecret = v
	}
	if v := os.Getenv("HG_ADMIN_SECRET"); v != "" {
		cfg.AdminSecret = v
	}
	if v := os.Getenv("HG_RATE_LIMIT_REQS"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			cfg.RateLimitReqs = n
		}
	}
	if v := os.Getenv("HG_RATE_LIMIT_WINDOW"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			cfg.RateLimitWindow = n
		}
	}
}

type handler struct {
	next           http.Handler
	name           string
	config         *Config
	mode           Mode
	cache          *cacheLayer
	detector       *detector
	hermes         *hermesClient
	banPage        []byte
	captchaPage    []byte
	geoip          *geoipDB
	blockCountries map[string]bool
	challCountries map[string]bool
	profileRules   map[string]string
	defaultAction  string
	respPatterns   []*regexp.Regexp
	excludedPaths  []*regexp.Regexp
	staticIPs      map[string]bool
	cidrNets       []*net.IPNet
	trustedNets    []*net.IPNet
	privateNets    []*net.IPNet
	mu             sync.RWMutex
	statsMu        sync.Mutex
	stats          handlerStats
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logger
	denyStatusCode int
	rateLimitPaths []struct {
		re      *regexp.Regexp
		maxReqs int
		window  int
	}
	honeypotRes  []*regexp.Regexp
	hostProfiles map[string]*hostProfileCfg
	ja3BlockMap  map[string]bool
	hermesBlocks int64
	hermesCorrect int64
	bodyInspectRes []*regexp.Regexp
}

type handlerStats struct {
	requests    int64
	blocked     int64
	challenged  int64
	allowed     int64
	rateHits    int64
	geoipBlocks int64
	respLeaks   int64
	turnstileOK int64
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	resolveConfig(config)

	ctx, cancel := context.WithCancel(ctx)
	logr := newLogger(LogLevel(config.LogLevel))

	h := &handler{
		next:           next,
		name:           name,
		config:         config,
		mode:           Mode(config.Mode),
		ctx:            ctx,
		cancel:         cancel,
		staticIPs:      make(map[string]bool),
		blockCountries: make(map[string]bool),
		challCountries: make(map[string]bool),
		logger:         logr,
	}

	if h.mode != ModeMonitor && h.mode != ModeProtect {
		h.mode = ModeMonitor
	}

	if h.config.HTTPStatusCodeDenied < 100 || h.config.HTTPStatusCodeDenied > 599 {
		h.config.HTTPStatusCodeDenied = 403
	}
	h.denyStatusCode = h.config.HTTPStatusCodeDenied
	h.privateNets = initPrivateIPBlocks()
	h.parseExcludedPaths()

	for _, c := range config.BlockCountries {
		h.blockCountries[strings.ToUpper(c)] = true
	}
	for _, c := range config.ChallengeCountries {
		h.challCountries[strings.ToUpper(c)] = true
	}

	h.parseIPLists()
	h.detector = newDetector(config.SuspiciousPatterns, config.PatternsFile,
		config.CollectionsDir, config.MaxBodySize, logr)
	h.loadPages()
	h.loadGeoIP()
	h.loadProfile()

	h.respPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`),
		regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*['"\w]+`),
		regexp.MustCompile(`(?i)-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY`),
	}

	h.initRateLimitPaths()
	h.initHoneypotPaths()
	h.initHostProfiles()
	h.initJA3BlockList()
	h.initBodyInspector()

	h.cache = newCacheLayer(config.RedisAddr, config.RedisPassword, config.RedisDB, config.CacheTTL,
		config.RedisTLSEnabled, config.RedisTLSSkipVerify, logr)
	h.seedStaticLists()

	if config.HermesEndpoint != "" {
		hc := newHermesClient(config.HermesEndpoint, config.HermesToken,
			config.HermesBlockWebhookURL, config.HermesBlockWebhookSecret,
			config.HermesTLSInsecure, config.HermesTLSCAFile, logr)
		if err := hc.HealthCheck(ctx); err != nil {
			logr.warn("Hermes Agent unreachable: %v", err)
			if config.HermesRetryEnabled {
				go h.hermesReconnectLoop(hc)
			}
		} else {
			h.hermes = hc
			logr.info("Hermes Agent connected: %s", maskEndpoint(config.HermesEndpoint))
		}
	}

	if config.PatternsFile != "" && config.PatternsWatchSec > 0 {
		go h.patternsWatchLoop()
	}
	if config.GeoIPDBFile != "" && config.GeoIPUpdateURL != "" && config.GeoIPUpdateIntervalH > 0 {
		go h.geoipUpdateLoop()
	}

	if !config.SilentStartUp {
		logr.info("config: mode=%s risk=%.2f admin=%v geoip=%v rateLimit=%d/%ds respInspect=%v local=%v excluded=%v adminSecret=%v",
			config.Mode, config.MinRiskScore, config.AdminEnabled,
			h.geoip != nil && h.geoip.IsLoaded(), config.RateLimitReqs, config.RateLimitWindow,
			config.InspectResponses, config.AllowLocalRequests, len(config.ExcludedPathPatterns),
			config.AdminSecret != "")
	}

	return h, nil
}

func (h *handler) loadPages() {
	if h.config.BanPageFile != "" {
		if data, err := os.ReadFile(h.config.BanPageFile); err == nil {
			h.banPage = data
			h.logger.info("loaded ban page: %s (%d bytes)", h.config.BanPageFile, len(data))
		}
	}
	if h.config.CaptchaPageFile != "" {
		if data, err := os.ReadFile(h.config.CaptchaPageFile); err == nil {
			h.captchaPage = data
			h.logger.info("loaded captcha page: %s (%d bytes)", h.config.CaptchaPageFile, len(data))
		}
	}
}

func (h *handler) loadGeoIP() {
	if h.config.GeoIPDBFile != "" {
		db, err := newGeoIPDB(h.config.GeoIPDBFile)
		if err != nil {
			h.logger.warn("geoip load failed: %v", err)
		} else {
			h.geoip = db
			h.logger.info("geoip loaded: %s", h.config.GeoIPDBFile)
		}
	}
}

func (h *handler) loadProfile() {
	h.profileRules = make(map[string]string)
	h.defaultAction = "ban"

	if h.config.ProfileFile == "" {
		return
	}

	data, err := os.ReadFile(h.config.ProfileFile)
	if err != nil {
		h.logger.warn("profile load failed: %v", err)
		return
	}

	var profile struct {
		Version int               `json:"version"`
		Rules   map[string]string `json:"rules"`
		Default string            `json:"default_action"`
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		h.logger.warn("profile parse failed: %v", err)
		return
	}

	for k, v := range profile.Rules {
		h.profileRules[k] = v
	}
	if profile.Default != "" {
		h.defaultAction = profile.Default
	}

	h.logger.info("profile loaded: %d rules, default=%s", len(h.profileRules), h.defaultAction)
}

func (h *handler) decideAction(category string, fallback string) string {
	if action, ok := h.profileRules[category]; ok {
		return action
	}
	if action, ok := h.profileRules[fallback]; ok {
		return action
	}
	return h.defaultAction
}

// ---- Background loops ----

func (h *handler) hermesReconnectLoop(hc *hermesClient) {
	interval := time.Duration(h.config.HermesRetryInterval) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	connected := false
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			if connected {
				return
			}
			if err := hc.HealthCheck(h.ctx); err != nil {
				h.logger.warn("Hermes Agent still unreachable: %v", err)
			} else {
				connected = true
				h.hermes = hc
				h.logger.info("Hermes Agent reconnected")
				return
			}
		}
	}
}

func (h *handler) patternsWatchLoop() {
	interval := time.Duration(h.config.PatternsWatchSec) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}
	var lastMod time.Time
	if fi, err := os.Stat(h.config.PatternsFile); err == nil {
		lastMod = fi.ModTime()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			fi, err := os.Stat(h.config.PatternsFile)
			if err != nil {
				continue
			}
			if fi.ModTime().After(lastMod) {
				lastMod = fi.ModTime()
				h.logger.info("patterns file changed, reloading...")
				h.detector.Reload()
			}
		}
	}
}

// ---- IP parsing ----

func (h *handler) parseExcludedPaths() {
	for _, pattern := range h.config.ExcludedPathPatterns {
		re, err := regexp.Compile(strings.TrimSpace(pattern))
		if err != nil {
			h.logger.warn("invalid excluded path pattern %q: %v", pattern, err)
			continue
		}
		h.excludedPaths = append(h.excludedPaths, re)
	}
	if len(h.excludedPaths) > 0 {
		h.logger.info("loaded %d excluded path patterns", len(h.excludedPaths))
	}
}

func initPrivateIPBlocks() []*net.IPNet {
	var blocks []*net.IPNet
	for _, cidr := range []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

func (h *handler) parseIPLists() {
	for _, entry := range h.config.IPWhitelist {
		h.addCIDR(entry, true)
	}
	for _, entry := range h.config.IPBlacklist {
		h.addCIDR(entry, true)
	}
	for _, entry := range h.config.TrustedProxies {
		h.addTrustedCIDR(entry)
	}
}

func (h *handler) addCIDR(entry string, isStatic bool) {
	_, ipNet, err := net.ParseCIDR(entry)
	if err == nil {
		h.cidrNets = append(h.cidrNets, ipNet)
		return
	}
	ip := net.ParseIP(entry)
	if ip != nil && isStatic {
		h.staticIPs[entry] = true
	}
}

func (h *handler) addTrustedCIDR(entry string) {
	_, ipNet, err := net.ParseCIDR(entry)
	if err == nil {
		h.trustedNets = append(h.trustedNets, ipNet)
		return
	}
	ip := net.ParseIP(entry)
	if ip != nil {
		_, ipNet, _ = net.ParseCIDR(entry + "/32")
		if ipNet != nil {
			h.trustedNets = append(h.trustedNets, ipNet)
		}
	}
}

func (h *handler) ipInList(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if h.staticIPs[ipStr] {
		return true
	}
	for _, n := range h.cidrNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (h *handler) seedStaticLists() {
	if h.cache == nil {
		return
	}
	for _, entry := range h.config.IPBlacklist {
		if _, _, err := net.ParseCIDR(entry); err == nil {
			continue
		}
		if net.ParseIP(entry) != nil {
			_ = h.cache.BlockIP(entry, 0)
		}
	}
	for _, entry := range h.config.IPWhitelist {
		if _, _, err := net.ParseCIDR(entry); err == nil {
			continue
		}
		if net.ParseIP(entry) != nil {
			_ = h.cache.WhitelistIP(entry)
		}
	}
}

func (h *handler) readStat(field *int64) int64 {
	h.statsMu.Lock()
	v := *field
	h.statsMu.Unlock()
	return v
}

// ---- Main handler ----

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if h.config.FallbackWhenError {
		defer func() {
			if r := recover(); r != nil {
				h.logger.warn("panic recovered: %v — passing through", r)
				h.next.ServeHTTP(w, req)
			}
		}()
	}

	h.statsMu.Lock()
	h.stats.requests++
	h.statsMu.Unlock()

	clientIP := h.extractClientIP(req)
	h.logger.debug("REQ ip=%s method=%s host=%s path=%s", clientIP, req.Method, req.Host, req.URL.RequestURI())

	// Hermes Agent callback API endpoints
	if strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/") {
		if !h.checkHermesAuth(req) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"status":"denied","reason":"invalid secret"}`))
			return
		}
		ip := req.URL.Query().Get("ip")
		ttl := req.URL.Query().Get("ttl")
		ttlSec, _ := strconv.Atoi(ttl)
		if ttlSec <= 0 {
			ttlSec = h.config.CacheTTL
		}

		switch {
		case strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/block"):
			if ip != "" && h.cache != nil {
				_ = h.cache.BlockIP(ip, ttlSec)
				h.logger.info("hermes-api: blocked %s ttl=%d", ip, ttlSec)
				w.Write([]byte(`{"status":"ok","action":"block","ip":"` + ip + `"}`))
			}
		case strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/challenge"):
			if ip != "" && h.cache != nil {
				h.cache.MarkChallenge(ip, ttlSec)
				h.logger.info("hermes-api: challenged %s ttl=%d", ip, ttlSec)
				w.Write([]byte(`{"status":"ok","action":"challenge","ip":"` + ip + `"}`))
			}
		case strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/whitelist"):
			if ip != "" && h.cache != nil {
				_ = h.cache.WhitelistIP(ip)
				h.logger.info("hermes-api: whitelisted %s ttl=%d", ip, ttlSec)
				w.Write([]byte(`{"status":"ok","action":"whitelist","ip":"` + ip + `"}`))
			}
		case strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/unblock"):
			if ip != "" && h.cache != nil {
				_ = h.cache.UnblockIP(ip)
				h.logger.info("hermes-api: unblocked %s", ip)
				w.Write([]byte(`{"status":"ok","action":"unblock","ip":"` + ip + `"}`))
			}
		case strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/unwhitelist"):
			if ip != "" && h.cache != nil {
				_ = h.cache.UnwhitelistIP(ip)
				h.logger.info("hermes-api: removed from whitelist %s", ip)
				w.Write([]byte(`{"status":"ok","action":"unwhitelist","ip":"` + ip + `"}`))
			}

		// ---- Collection management ----
		case strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/collections/list"):
			h.handleCollectionsList(w)
		case strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/collections/update"):
			if req.Method == http.MethodPost {
				h.handleCollectionsUpdate(w, req)
			} else {
				w.Write([]byte(`{"status":"error","reason":"use POST"}`))
			}
		case strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/collections/delete"):
			name := req.URL.Query().Get("name")
			if name != "" {
				h.handleCollectionsDelete(w, name)
			} else {
				w.Write([]byte(`{"status":"error","reason":"missing name"}`))
			}
		case strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/collections/reload"):
			h.detector.Reload()
			h.logger.info("collections reloaded")
			w.Write([]byte(`{"status":"ok","action":"reload"}`))
		case strings.HasPrefix(req.URL.Path, "/.hermes-guard/api/status"):
			if ip == "" {
				w.Write([]byte(`{"status":"error","reason":"missing ip"}`))
				break
			}
			blocked := false
			whitelisted := false
			if h.cache != nil {
				blocked, _ = h.cache.IsBlocked(ip)
				whitelisted, _ = h.cache.IsWhitelisted(ip)
			}
			state := "unknown"
			if blocked {
				state = "blocked"
			} else if whitelisted {
				state = "whitelisted"
			}
			resp, _ := json.Marshal(map[string]interface{}{
				"status":      "ok",
				"ip":          ip,
				"state":       state,
				"blocked":     blocked,
				"whitelisted": whitelisted,
			})
			w.Header().Set("Content-Type", "application/json")
			w.Write(resp)
		default:
			w.Write([]byte(`{"status":"error","reason":"unknown endpoint"}`))
		}
		return
	}

	// API: unblock IP (call == by Hermes Agent — requires shared secret + local IP)
	if strings.HasPrefix(req.URL.Path, "/.hermes-guard/unblock") {
		ip := req.URL.Query().Get("ip")
		secret := req.URL.Query().Get("secret")

		allowed := false
		if secret != "" {
			if h.config.AdminSecret != "" {
				allowed = secret == h.config.AdminSecret
			} else if h.config.HermesBlockWebhookSecret != "" {
				allowed = secret == h.config.HermesBlockWebhookSecret
			}
		}
		if !allowed {
			h.logger.warn("unblock denied: secret configured=%v received=%q",
				h.config.AdminSecret != "" || h.config.HermesBlockWebhookSecret != "", secret)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"status":"denied","reason":"invalid secret"}`))
			return
		}

		if h.cache != nil && ip != "" {
			_ = h.cache.UnblockIP(ip)
			h.logger.info("api: unblocked %s", ip)
			if h.hermes != nil {
				h.hermes.NotifyUnblock(ip, h.config.HermesBlockWebhookSecret)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok","ip":"` + ip + `"}`))
		} else {
			w.Write([]byte(`{"status":"error","reason":"no cache or empty ip"}`))
		}
		return
	}

	// Health check (no auth required)
	if req.URL.Path == "/.hermes-guard/health" {
		h.healthCheck(w, req)
		return
	}

	// Admin dashboard & metrics
	if h.config.AdminEnabled {
		if req.URL.Path == "/.hermes-guard/admin" {
			if !h.checkAdminAuth(req) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Access Denied","reason":"invalid secret"}`))
				return
			}
			h.serveAdmin(w, req)
			return
		}
		if req.URL.Path == "/.hermes-guard/admin/unblock" && req.Method == http.MethodPost {
			if !h.checkAdminAuth(req) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Access Denied","reason":"invalid secret"}`))
				return
			}
			ip := req.FormValue("ip")

			if ip != "" && h.cache != nil {
				_ = h.cache.UnblockIP(ip)
				h.logger.info("admin: unblocked %s", ip)
				if h.hermes != nil {
					h.hermes.NotifyUnblock(ip, h.config.HermesBlockWebhookSecret)
				}
			}
			http.Redirect(w, req, "/.hermes-guard/admin", http.StatusFound)
			return
		}
		if req.URL.Path == "/.hermes-guard/metrics" {
			if !h.checkAdminAuth(req) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Access Denied","reason":"invalid secret"}`))
				return
			}
			h.serveMetrics(w)
			return
		}
		if req.URL.Path == "/.hermes-guard/feedback" {
			if !h.checkAdminAuth(req) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			h.serveFeedbackStats(w)
			return
		}
		if req.URL.Path == "/.hermes-guard/audit" {
			if !h.checkAdminAuth(req) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			h.serveAuditExport(w, req)
			return
		}
		if req.URL.Path == "/.hermes-guard/stream" {
			if !h.checkAdminAuth(req) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			h.serveSSE(w, req)
			return
		}
	}

	// Scheduled blocking rules
	if active, action := h.isScheduledActive(); active {
		if action == "captcha" && h.config.TurnstileSecretKey != "" {
			h.challengeRequest(w, req, "scheduled_rule")
		} else {
			h.blockRequest(w, req, "scheduled_rule")
		}
		return
	}

	// JA3 fingerprint check (before all other checks)
	if len(h.ja3BlockMap) > 0 {
		ja3 := h.extractJA3(req)
		if h.ja3BlockMap[ja3] {
			h.blockRequest(w, req, "ja3_blocklist:"+ja3)
			return
		}
	}

	// Excluded path patterns (health checks, webhooks, etc.)
	if h.isPathExcluded(req.Host + req.URL.Path) {
		h.next.ServeHTTP(w, req)
		return
	}

	// Allow local/private requests
	parsedIP := net.ParseIP(clientIP)
	if h.config.AllowLocalRequests && parsedIP != nil && h.isPrivateIP(parsedIP) {
		h.logger.info("ALLOW local ip=%s path=%s", clientIP, req.URL.RequestURI())
		h.next.ServeHTTP(w, req)
		return
	}

	// Turnstile token verification
	if token := req.URL.Query().Get("hg_token"); token != "" {
		h.handleTurnstile(w, req, token, clientIP)
		return
	}

	// ---- GeoIP country blocking ----
	country := ""
	if h.geoip != nil && h.geoip.IsLoaded() {
		country = h.geoip.Lookup(clientIP)

		// Inject country header for downstream
		if h.config.AddCountryHeader && country != "" {
			req.Header.Set("X-IPCountry", country)
		}

		// Block countries — blackListMode inverts logic
		isBlocked := h.blockCountries[country]
		isChallenged := h.challCountries[country]
		if h.config.BlackListMode {
			isBlocked = !isBlocked && country != ""
		}

		if isBlocked {
			h.statsMu.Lock()
			h.stats.geoipBlocks++
			h.statsMu.Unlock()
			if h.decideAction("geoip", "") == "captcha" && h.config.TurnstileSecretKey != "" {
				h.challengeRequest(w, req, "geoip_block:"+country)
			} else {
				h.blockRequest(w, req, "geoip_block:"+country)
			}
			h.notifyWebhook(clientIP, req, "geoip_block:"+country, 1.0)
			h.auditLog(clientIP, req, "geoip_block:"+country, 1.0)
			return
		}
		if isChallenged && h.config.TurnstileSecretKey != "" {
			h.challengeRequest(w, req, "geoip_challenge:"+country)
			return
		}
	}

	// ---- Layer 1: Lua L1 (blocklist + whitelist) ----
	if h.cache != nil {
		blocked, whitelisted, _, err := h.cache.EvalL1(clientIP)
		if err == nil {
			h.logger.debug("L1: ip=%s blocked=%v whitelisted=%v err=%v", clientIP, blocked, whitelisted, err)
			if blocked {
				h.blockRequest(w, req, "cache_blacklist")
				return
			}
			if whitelisted || h.matchesStaticWhitelist(clientIP) {
				h.passThrough(w, req)
				return
			}
		} else {
			h.logger.warn("L1 eval failed: ip=%s err=%v — using fallback", clientIP, err)
		}
	}

	// Fallback whitelist check (non-Lua path)
	if h.cache != nil {
		if blocked, _ := h.cache.IsBlocked(clientIP); blocked {
			h.blockRequest(w, req, "cache_blacklist_fallback")
			return
		}
		if whitelisted, _ := h.cache.IsWhitelisted(clientIP); whitelisted {
			h.logger.info("L1 fallback: ip=%s whitelisted=true — passing through", clientIP)
			h.passThrough(w, req)
			return
		}
	}

	// ---- Layer 1: Rate Limiting ----
	if h.config.RateLimitReqs > 0 && h.cache != nil {
		if allowed, _ := h.cache.RateLimitCheck(clientIP, h.config.RateLimitReqs, h.config.RateLimitWindow); !allowed {
			h.statsMu.Lock()
			h.stats.rateHits++
			h.statsMu.Unlock()
			_ = h.cache.BlockIP(clientIP, h.config.RateLimitBlockTTL)
			if h.decideAction("rate_limit", "") == "captcha" && h.config.TurnstileSecretKey != "" {
				h.challengeRequest(w, req, "rate_limit")
			} else {
				h.blockRequest(w, req, "rate_limit")
			}
			h.notifyWebhook(clientIP, req, "rate_limit", 1.0)
			h.auditLog(clientIP, req, "rate_limit", 1.0)
			return
		}
	}

	// Per-path rate limiting
	if len(h.rateLimitPaths) > 0 && h.cache != nil {
		if maxReqs, window := h.getPathRateLimit(req.URL.Path); maxReqs > 0 {
			if allowed, _ := h.cache.RateLimitCheck(clientIP+"@path", maxReqs, window); !allowed {
				_ = h.cache.BlockIP(clientIP, h.config.RateLimitBlockTTL)
				h.blockRequest(w, req, "path_rate_limit:"+req.URL.Path)
				h.notifySlack(clientIP, req, "path_rate_limit:"+req.URL.Path, 1.0)
				return
			}
		}
	}

	// Honeypot detection
	if h.checkHoneypot(req.URL.Path) {
		h.logger.warn("HONEYPOT: ip=%s path=%s", clientIP, req.URL.RequestURI())
		h.blockRequest(w, req, "honeypot:"+req.URL.Path)
		h.notifySlack(clientIP, req, "honeypot:"+req.URL.Path, 1.0)
		h.hermes.NotifyBlock(WebhookEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			ClientIP:  clientIP, Host: req.Host, Method: req.Method,
			Path: req.URL.RequestURI(), Reason: "honeypot:" + req.URL.Path, Verdict: "block",
		})
		h.auditLog(clientIP, req, "honeypot:"+req.URL.Path, 1.0)
		return
	}

	// AbuseIPDB check
	if h.checkAbuseIPDB(clientIP) {
		h.logger.info("ABUSEIPDB: ip=%s known malicious", clientIP)
		_ = h.cache.BlockIP(clientIP, h.config.CacheTTL)
		h.blockRequest(w, req, "abuseipdb")
		h.notifySlack(clientIP, req, "abuseipdb", 1.0)
		return

	}

	// Fallback static list checks
	if h.ipInStaticBlacklist(clientIP) {
		h.blockRequest(w, req, "static_blacklist")
		return
	}
	if h.cache != nil {
		if blocked, _ := h.cache.IsBlocked(clientIP); blocked {
			h.blockRequest(w, req, "cache_blacklist_fallback")
			return
		}
		if whitelisted, _ := h.cache.IsWhitelisted(clientIP); whitelisted {
			h.passThrough(w, req)
			return
		}
	}

	// Hermes-ordered challenge
	if h.cache != nil && h.cache.IsChallenged(clientIP) {
		h.challengeRequest(w, req, "hermes_challenge:"+clientIP)
		return
	}

	// ---- Layer 1: Fast-Path Detection ----
	detection := h.detector.Analyze(req)

	if detection.IsSuspicious {
		h.logSecurityEvent(clientIP, req, detection, "")
		h.sendAnalyzeTelemetry(clientIP, req, detection)
	}

	if h.mode == ModeProtect && detection.RiskScore >= h.config.MinRiskScore {
		h.logger.info("BLOCK TRIGGER: risk=%.2f >= threshold=%.2f mode=%s category=%s",
			detection.RiskScore, h.config.MinRiskScore, h.config.Mode, detection.Category)
		if h.cache != nil {
			_ = h.cache.BlockIP(clientIP, h.config.CacheTTL)
		}
		category := detection.Category
		if category == "" {
			category = "fast_path"
		}
		if h.decideAction(category, "fast_path") == "captcha" && h.config.TurnstileSecretKey != "" {
			h.challengeRequest(w, req, "fast_path_detection:"+category)
		} else {
			h.blockRequest(w, req, "fast_path_detection:"+category)
		}
		h.logSecurityEvent(clientIP, req, detection, VerdictBlock)
		h.inspectRequestBody(detection.BodyBytes, clientIP, req.URL.Path)
		h.notifyWebhook(clientIP, req, "fast_path_detection:"+category, detection.RiskScore)
		h.auditLog(clientIP, req, "fast_path_detection:"+category, detection.RiskScore)
		return
	}

	// ---- Response inspection ----
	if h.config.InspectResponses {
		rw := &respInspector{
			w:        w,
			handler:  h,
			clientIP: clientIP,
			req:      req,
		}
		h.next.ServeHTTP(rw, rw.req)
		return
	}

	h.statsMu.Lock()
	h.stats.allowed++
	h.statsMu.Unlock()
	h.passThrough(w, req)
}

// ---- Response Inspector ----

type respInspector struct {
	w          http.ResponseWriter
	handler    *handler
	clientIP   string
	req        *http.Request
	body       bytes.Buffer
	wroteHeader bool
}

func (r *respInspector) Header() http.Header {
	return r.w.Header()
}

func (r *respInspector) WriteHeader(code int) {
	r.wroteHeader = true
	r.w.WriteHeader(code)
}

func (r *respInspector) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	if r.body.Len() < 65536 {
		r.body.Write(b)
	}
	r.inspect()
	return r.w.Write(b)
}

func (r *respInspector) inspect() {
	if r.body.Len() == 0 {
		return
	}
	bodyStr := r.body.String()
	for _, p := range r.handler.respPatterns {
		if p.MatchString(bodyStr) {
			r.handler.statsMu.Lock()
			r.handler.stats.respLeaks++
			r.handler.statsMu.Unlock()
			r.handler.logger.warn("response leak detected: ip=%s path=%s pattern=%s",
				r.clientIP, r.req.URL.RequestURI(), p.String())
			break
		}
	}
}

// ---- Turnstile ----

func (h *handler) handleTurnstile(w http.ResponseWriter, req *http.Request, token, clientIP string) {
	if h.cache != nil {
		if allowed, _ := h.cache.CheckTurnstileRateLimit(clientIP); !allowed {
			h.blockRequest(w, req, "turnstile_rate_limit")
			return
		}
	}
	if h.config.TurnstileSecretKey == "" {
		h.challengeRequest(w, req, "turnstile_not_configured")
		return
	}
	verified, err := verifyTurnstile(token, h.config.TurnstileSecretKey, clientIP)
	if err != nil {
		h.logger.warn("turnstile verify error: %v", err)
		h.challengeRequest(w, req, "turnstile_failed")
		return
	}
	if verified {
		h.statsMu.Lock()
		h.stats.turnstileOK++
		h.statsMu.Unlock()
		if h.cache != nil {
			_ = h.cache.UnblockIP(clientIP)
			_ = h.cache.ClearChallenge(clientIP)
			_ = h.cache.WhitelistIP(clientIP)
			_ = h.cache.ResetTurnstileCounter(clientIP)
		}
		cleanURL := stripQueryParam(req.URL, "hg_token")
		if h.cache != nil {
			blocked, _ := h.cache.IsBlocked(clientIP)
			whitelisted, _ := h.cache.IsWhitelisted(clientIP)
			h.logger.info("captcha passed: ip=%s blocked=%v whitelisted=%v url=%s",
				clientIP, blocked, whitelisted, cleanURL.String())
		}
		http.Redirect(w, req, cleanURL.String(), http.StatusFound)
		return
	}
	h.challengeRequest(w, req, "turnstile_failed")
}

// ---- Admin & Metrics ----

func (h *handler) serveAdmin(w http.ResponseWriter, req *http.Request) {
	stats := h.cache.Stats()
	statsJSON, _ := json.MarshalIndent(stats, "", "  ")

	page := adminHTML
	page = strings.Replace(page, "{{REQUESTS}}", fmt.Sprintf("%d", h.readStat(&h.stats.requests)), 1)
	page = strings.Replace(page, "{{ALLOWED}}", fmt.Sprintf("%d", h.readStat(&h.stats.allowed)), 1)
	page = strings.Replace(page, "{{BLOCKED}}", fmt.Sprintf("%d", h.readStat(&h.stats.blocked)), 1)
	page = strings.Replace(page, "{{CHALLENGED}}", fmt.Sprintf("%d", h.readStat(&h.stats.challenged)), 1)
	page = strings.Replace(page, "{{RATE_HITS}}", fmt.Sprintf("%d", h.readStat(&h.stats.rateHits)), 1)
	page = strings.Replace(page, "{{GEOIP}}", fmt.Sprintf("%d", h.readStat(&h.stats.geoipBlocks)), 1)
	page = strings.Replace(page, "{{LEAKS}}", fmt.Sprintf("%d", h.readStat(&h.stats.respLeaks)), 1)
	page = strings.Replace(page, "{{TURNSTILE}}", fmt.Sprintf("%d", h.readStat(&h.stats.turnstileOK)), 1)
	page = strings.Replace(page, "{{CACHE_STATS}}", string(statsJSON), 1)
	page = strings.Replace(page, "{{SECRET}}", h.config.AdminSecret, -1)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(page))
}

func (h *handler) serveMetrics(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	fmt.Fprintf(w, "# HELP hermes_guard_requests_total By verdict.\n")
	fmt.Fprintf(w, "# TYPE hermes_guard_requests_total counter\n")
	fmt.Fprintf(w, "hermes_guard_requests_total{verdict=\"allowed\"} %d\n", h.readStat(&h.stats.allowed))
	fmt.Fprintf(w, "hermes_guard_requests_total{verdict=\"blocked\"} %d\n", h.readStat(&h.stats.blocked))
	fmt.Fprintf(w, "hermes_guard_requests_total{verdict=\"challenged\"} %d\n", h.readStat(&h.stats.challenged))
	fmt.Fprintf(w, "# HELP hermes_guard_requests_count Total requests.\n")
	fmt.Fprintf(w, "# TYPE hermes_guard_requests_count counter\n")
	fmt.Fprintf(w, "hermes_guard_requests_count %d\n", h.readStat(&h.stats.requests))
	fmt.Fprintf(w, "# HELP hermes_guard_rate_limit_hits Rate limit triggers.\n")
	fmt.Fprintf(w, "# TYPE hermes_guard_rate_limit_hits counter\n")
	fmt.Fprintf(w, "hermes_guard_rate_limit_hits %d\n", h.readStat(&h.stats.rateHits))
	fmt.Fprintf(w, "# HELP hermes_guard_geoip_blocks GeoIP country blocks.\n")
	fmt.Fprintf(w, "# TYPE hermes_guard_geoip_blocks counter\n")
	fmt.Fprintf(w, "hermes_guard_geoip_blocks %d\n", h.readStat(&h.stats.geoipBlocks))
	fmt.Fprintf(w, "# HELP hermes_guard_response_leaks Response data leaks.\n")
	fmt.Fprintf(w, "# TYPE hermes_guard_response_leaks counter\n")
	fmt.Fprintf(w, "hermes_guard_response_leaks %d\n", h.readStat(&h.stats.respLeaks))
	fmt.Fprintf(w, "# HELP hermes_guard_turnstile_successes Turnstile verifications.\n")
	fmt.Fprintf(w, "# TYPE hermes_guard_turnstile_successes counter\n")
	fmt.Fprintf(w, "hermes_guard_turnstile_successes %d\n", h.readStat(&h.stats.turnstileOK))
}

// ---- Response rendering ----

func (h *handler) passThrough(w http.ResponseWriter, req *http.Request) {
	h.next.ServeHTTP(w, req)
}

func (h *handler) blockRequest(w http.ResponseWriter, req *http.Request, reason string) {
	h.statsMu.Lock()
	h.stats.blocked++
	h.statsMu.Unlock()

	hermesStatus := "disconnected"
	if h.config.HermesEndpoint != "" {
		hermesStatus = "connected:" + maskEndpoint(h.config.HermesEndpoint)
	}
	h.logger.info("BLOCK ip=%s method=%s path=%s reason=%s hermes=%s",
		h.extractClientIP(req), req.Method, req.URL.RequestURI(), reason, hermesStatus)

	// Notify Hermes Agent
	if h.hermes != nil {
		h.hermes.NotifyBlock(WebhookEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			ClientIP:  h.extractClientIP(req),
			Host:      req.Host,
			Method:    req.Method,
			Path:      req.URL.RequestURI(),
			Reason:    reason,
			Verdict:   "block",
		})
	}

	h.notifySlack(h.extractClientIP(req), req, reason, 0)
	w.Header().Set("X-Hermes-Reason", reason)

	if h.config.RedirectURLIfDenied != "" {
		http.Redirect(w, req, h.config.RedirectURLIfDenied, http.StatusFound)
		return
	}

	w.WriteHeader(h.denyStatusCode)

	if len(h.banPage) > 0 {
		page := h.banPage
		page = bytes.Replace(page, []byte("{{.ClientIP}}"), []byte(clientID(req)), 1)
		page = bytes.Replace(page, []byte("{{.Reason}}"), []byte(reason), 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
		return
	}
	w.Write([]byte(`{"error":"Access Denied","reason":"Security policy violation"}`))
}

func (h *handler) challengeRequest(w http.ResponseWriter, req *http.Request, reason string) {
	h.statsMu.Lock()
	h.stats.challenged++
	h.statsMu.Unlock()

	h.logger.info("CHALLENGE ip=%s method=%s path=%s reason=%s",
		h.extractClientIP(req), req.Method, req.URL.RequestURI(), reason)

	w.Header().Set("X-Hermes-Guard", "challenge")

	if len(h.captchaPage) > 0 {
		page := h.captchaPage
		page = bytes.Replace(page, []byte("{{.ClientIP}}"), []byte(clientID(req)), 1)
		page = bytes.Replace(page, []byte("{{.Reason}}"), []byte(reason), 1)
		if h.config.TurnstileSiteKey != "" {
			page = bytes.Replace(page, []byte("TURNSTILE_SITE_KEY"), []byte(h.config.TurnstileSiteKey), 1)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		w.Write(page)
		return
	}

	challengeURL := h.config.ChallengeURL
	if challengeURL == "" {
		challengeURL = "/.hermes-guard/challenge"
	}
	http.Redirect(w, req, fmt.Sprintf("%s?rid=%s&reason=%s", challengeURL, clientID(req), reason), http.StatusFound)
}

// ---- Telemetry ----

func verifyTurnstile(token, secretKey, clientIP string) (bool, error) {
	type turnstileResp struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	payload := fmt.Sprintf("secret=%s&response=%s&remoteip=%s", secretKey, token, clientIP)
	resp, err := http.Post("https://challenges.cloudflare.com/turnstile/v0/siteverify",
		"application/x-www-form-urlencoded", strings.NewReader(payload))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var tr turnstileResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return false, err
	}
	if !tr.Success {
		return false, fmt.Errorf("turnstile: %v", tr.ErrorCodes)
	}
	return true, nil
}

// ---- Telemetry to Hermes Analyze ----

func (h *handler) sendAnalyzeTelemetry(clientIP string, req *http.Request, detection *DetectionResult) {
	if h.config.HermesAnalyzeURL == "" || h.config.HermesEndpoint == "" {
		return
	}

	// Build target URL from endpoint base + analyze path
	u, err := url.Parse(h.config.HermesEndpoint)
	if err != nil {
		return
	}
	u.Path, _ = url.JoinPath(u.Path, h.config.HermesAnalyzeURL)
	target := u.String()

	bodySnippet := ""
	if len(detection.BodyBytes) > 0 {
		maxLen := 2048
		if len(detection.BodyBytes) < maxLen {
			maxLen = len(detection.BodyBytes)
		}
		bodySnippet = string(detection.BodyBytes[:maxLen])
	}

	payload := map[string]interface{}{
		"ip":               clientIP,
		"path":             req.URL.RequestURI(),
		"method":           req.Method,
		"host":             req.Host,
		"risk_score":       detection.RiskScore,
		"categories":       []string{detection.Category},
		"matched_patterns": detection.MatchedPatterns,
		"body_snippet":     bodySnippet,
		"content_type":     req.Header.Get("Content-Type"),
		"user_agent":       req.UserAgent(),
		"reason":           detection.Reason,
	}

	data, _ := json.Marshal(payload)

	go func() {
		req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		mac := hmac.New(sha256.New, []byte(h.config.HermesBlockWebhookSecret))
		mac.Write(data)
		sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Hub-Signature-256", sig)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			h.logger.debug("hermes analyze failed: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

func (h *handler) logSecurityEvent(clientIP string, req *http.Request, detection *DetectionResult, verdict Verdict) {
	parts := []string{
		"ip=" + clientIP,
		"method=" + req.Method,
		"path=" + req.URL.RequestURI(),
		fmt.Sprintf("risk=%.2f", detection.RiskScore),
	}
	if len(detection.MatchedPatterns) > 0 {
		parts = append(parts, "patterns="+strings.Join(detection.MatchedPatterns, ","))
	}
	if verdict != "" {
		parts = append(parts, "verdict="+string(verdict))
	}
	if detection.Reason != "" {
		parts = append(parts, "reason="+detection.Reason)
	}
	h.logger.info("security event: %s", strings.Join(parts, " "))
}

// ---- Audit Log ----

func (h *handler) auditLog(clientIP string, req *http.Request, reason string, riskScore float64) {
	if h.cache == nil {
		return
	}
	entry, _ := json.Marshal(map[string]interface{}{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"client_ip":  clientIP,
		"method":     req.Method,
		"path":       req.URL.RequestURI(),
		"reason":     reason,
		"risk_score": riskScore,
		"host":       req.Host,
	})
	_ = h.cache.AuditLog(string(entry))
}

// ---- Webhook ----

func (h *handler) notifyWebhook(clientIP string, req *http.Request, reason string, riskScore float64) {
	if h.config.WebhookURL == "" {
		return
	}
	event := WebhookEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		ClientIP:  clientIP,
		Host:      req.Host,
		Method:    req.Method,
		Path:      req.URL.RequestURI(),
		Reason:    reason,
		RiskScore: riskScore,
		Verdict:   "block",
	}
	go func() {
		data, _ := json.Marshal(event)
		resp, err := http.Post(h.config.WebhookURL, "application/json", bytes.NewReader(data))
		if err != nil {
			h.logger.debug("webhook failed: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

// ---- IP Logic ----

func (h *handler) extractClientIP(req *http.Request) string {
	// Cloudflare: CF-Connecting-IP is the original client IP (only when enabled)
	if h.config.TrustCFHeaders {
		if cfIP := req.Header.Get("CF-Connecting-IP"); cfIP != "" {
			if ip := net.ParseIP(strings.TrimSpace(cfIP)); ip != nil {
				return ip.String()
			}
		}
		// Cloudflare country header for GeoIP lookup
		if cfCountry := req.Header.Get("CF-IPCountry"); cfCountry != "" && h.config.AddCountryHeader {
			req.Header.Set("X-IPCountry", cfCountry)
		}
	}

	if len(h.trustedNets) > 0 {
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				parsed := net.ParseIP(ip)
				if parsed == nil {
					continue
				}
				for _, tn := range h.trustedNets {
					if tn.Contains(parsed) {
						if i+1 < len(parts) {
							candidate := strings.TrimSpace(parts[i+1])
							if net.ParseIP(candidate) != nil {
								return candidate
							}
						}
						return ip
					}
				}
			}
		}
	}
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil && h.isTrustedProxy(req.RemoteAddr) {
			return ip
		}
	}
	host, _, _ := net.SplitHostPort(req.RemoteAddr)
	if host == "" {
		return req.RemoteAddr
	}
	return host
}

func (h *handler) isTrustedProxy(addr string) bool {
	if len(h.trustedNets) == 0 {
		return false
	}
	host, _, _ := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range h.trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (h *handler) ipInStaticBlacklist(ip string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ipInList(ip)
}

func (h *handler) matchesStaticWhitelist(ip string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ipInList(ip)
}

// ---- Collection Management ----

func (h *handler) handleCollectionsList(w http.ResponseWriter) {
	dir := h.config.CollectionsDir
	if dir == "" {
		dir = "/etc/traefik/collections"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.Write([]byte(`{"status":"error","reason":"` + err.Error() + `"}`))
		return
	}
	var files []map[string]interface{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			data, _ := os.ReadFile(dir + "/" + e.Name())
			var pf patternsFile
			if json.Unmarshal(data, &pf) == nil {
				files = append(files, map[string]interface{}{
					"name":     strings.TrimSuffix(e.Name(), ".json"),
					"category": pf.Category,
					"patterns": len(pf.Patterns),
					"loaded":   h.isCollectionLoaded(strings.TrimSuffix(e.Name(), ".json")),
				})
			}
		}
	}
	resp, _ := json.Marshal(files)
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func (h *handler) handleCollectionsUpdate(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		w.Write([]byte(`{"status":"error","reason":"read body failed"}`))
		return
	}

	var pf patternsFile
	if err := json.Unmarshal(body, &pf); err != nil {
		w.Write([]byte(`{"status":"error","reason":"invalid JSON: ` + err.Error() + `"}`))
		return
	}

	name := req.URL.Query().Get("name")
	if name == "" {
		name = pf.Category
	}
	if name == "" {
		w.Write([]byte(`{"status":"error","reason":"missing collection name"}`))
		return
	}

	dir := h.config.CollectionsDir
	if dir == "" {
		dir = "/etc/traefik/collections"
	}

	path := dir + "/" + name + ".json"
	if err := os.WriteFile(path, body, 0644); err != nil {
		w.Write([]byte(`{"status":"error","reason":"write failed: ` + err.Error() + `"}`))
		return
	}

	h.detector.Reload()
	h.logger.info("collection updated: %s (%d patterns)", name, len(pf.Patterns))
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","action":"updated","name":"` + name + `","patterns":` + strconv.Itoa(len(pf.Patterns)) + `}`))
}

func (h *handler) handleCollectionsDelete(w http.ResponseWriter, name string) {
	dir := h.config.CollectionsDir
	if dir == "" {
		dir = "/etc/traefik/collections"
	}

	path := dir + "/" + name + ".json"
	if err := os.Remove(path); err != nil {
		w.Write([]byte(`{"status":"error","reason":"` + err.Error() + `"}`))
		return
	}

	h.detector.Reload()
	h.logger.info("collection deleted: %s", name)
	w.Write([]byte(`{"status":"ok","action":"deleted","name":"` + name + `"}`))
}

func (h *handler) isCollectionLoaded(name string) bool {
	dir := h.config.CollectionsDir
	if dir == "" {
		dir = "/etc/traefik/collections"
	}
	_, err := os.Stat(dir + "/" + name + ".json")
	return err == nil
}

func (h *handler) healthCheck(w http.ResponseWriter, req *http.Request) {
	redisOK := "ok"
	if h.cache != nil {
		if err := h.cache.Ping(); err != nil {
			redisOK = "error: " + err.Error()
		}
	}
	hermesOK := "not configured"
	if h.config.HermesEndpoint != "" {
		hermesOK = "connected"
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","redis":"%s","hermes":"%s","mode":"%s","version":"2.0.0"}`, redisOK, hermesOK, h.config.Mode)
}

func (h *handler) checkAdminAuth(req *http.Request) bool {
	if h.config.AdminSecret == "" {
		return true
	}
	secret := req.URL.Query().Get("secret")
	if secret == "" {
		secret = req.FormValue("secret")
	}
	return secret == h.config.AdminSecret
}

func (h *handler) checkHermesAuth(req *http.Request) bool {
	secret := req.URL.Query().Get("secret")
	if secret == "" {
		return false
	}
	if h.config.AdminSecret != "" {
		return secret == h.config.AdminSecret
	}
	if h.config.HermesBlockWebhookSecret != "" {
		return secret == h.config.HermesBlockWebhookSecret
	}
	return false
}
func (h *handler) initRateLimitPaths() {
	for _, rp := range h.config.RateLimitPaths {
		re, err := regexp.Compile(rp.Path)
		if err != nil {
			h.logger.warn("invalid rate limit path %q: %v", rp.Path, err)
			continue
		}
		h.rateLimitPaths = append(h.rateLimitPaths, struct {
			re      *regexp.Regexp
			maxReqs int
			window  int
		}{re, rp.MaxReqs, rp.Window})
	}
}

func (h *handler) initHoneypotPaths() {
	for _, pattern := range h.config.HoneypotPaths {
		re, err := regexp.Compile(pattern)
		if err != nil { continue }
		h.honeypotRes = append(h.honeypotRes, re)
	}
}

func (h *handler) initHostProfiles() {
	h.hostProfiles = make(map[string]*hostProfileCfg)
	for _, hp := range h.config.HostProfiles {
		h.hostProfiles[hp.Host] = &hostProfileCfg{
			mode: hp.Mode, minRiskScore: hp.MinRiskScore, blockCountries: hp.BlockCountries,
		}
	}
}

type hostProfileCfg struct {
	mode           string
	minRiskScore   float64
	blockCountries []string
}

func (h *handler) checkHoneypot(path string) bool {
	for _, re := range h.honeypotRes {
		if re.MatchString(path) { return true }
	}
	return false
}

func (h *handler) getPathRateLimit(path string) (int, int) {
	for _, rp := range h.rateLimitPaths {
		if rp.re.MatchString(path) { return rp.maxReqs, rp.window }
	}
	return 0, 0
}

func (h *handler) checkAbuseIPDB(ip string) bool {
	if h.config.AbuseIPDBKey == "" || h.config.AbuseIPDBThreshold <= 0 { return false }
	u := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Key", h.config.AbuseIPDBKey)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return false }
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if data, ok := result["data"].(map[string]interface{}); ok {
		if score, ok := data["abuseConfidenceScore"].(float64); ok {
			return int(score) >= h.config.AbuseIPDBThreshold
		}
	}
	return false
}

func (h *handler) notifySlack(clientIP string, req *http.Request, reason string, riskScore float64) {
	if h.config.WebhookURL == "" { return }
	color := "#dc2626"
	if strings.Contains(reason, "captcha") { color = "#f59e0b" }
	msg := map[string]interface{}{
		"attachments": []map[string]interface{}{{
			"color": color,
			"title": "Blocked Request",
			"fields": []map[string]string{
				{"title": "IP", "value": clientIP, "short": "true"},
				{"title": "Method", "value": req.Method, "short": "true"},
				{"title": "Path", "value": req.URL.RequestURI()},
				{"title": "Host", "value": req.Host, "short": "true"},
				{"title": "Reason", "value": reason, "short": "true"},
				{"title": "Risk", "value": fmt.Sprintf("%.2f", riskScore), "short": "true"},
			},
			"footer": "Hermes Guard",
		}},
	}
	data, _ := json.Marshal(msg)
	go func() {
		resp, err := http.Post(h.config.WebhookURL, "application/json", bytes.NewReader(data))
		if err != nil { return }
		resp.Body.Close()
	}()
}
func (h *handler) initJA3BlockList() {
	h.ja3BlockMap = make(map[string]bool)
	for _, f := range h.config.JA3BlockList {
		h.ja3BlockMap[strings.TrimSpace(f)] = true
	}
}

func (h *handler) initBodyInspector() {
	h.bodyInspectRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(\b(?:union|select|insert|update|delete|drop|alter)\b.*\b(?:from|into|table|where|values|set|database)\b)`),
		regexp.MustCompile(`(?i)(\b(?:0x[0-9a-fA-F]+)\b)`),
		regexp.MustCompile(`(?i)(\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(.*\)\b)`),
		regexp.MustCompile(`(?i)(\b(?:cmd|command|exec|shell|bash|powershell)\b\s*[=:])`),
	}
}

func (h *handler) inspectRequestBody(body []byte, clientIP, path string) {
	if len(body) == 0 {
		return
	}
	bodyStr := string(body)
	for _, re := range h.bodyInspectRes {
		if re.MatchString(bodyStr) {
			h.logger.warn("BODY MATCH: ip=%s path=%s pattern=%s", clientIP, path, re.String())
			break
		}
	}
}

func (h *handler) geoipUpdateLoop() {
	interval := time.Duration(h.config.GeoIPUpdateIntervalH) * time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.logger.info("geoip: fetching update from %s", h.config.GeoIPUpdateURL)
			resp, err := http.Get(h.config.GeoIPUpdateURL)
			if err != nil {
				h.logger.warn("geoip update failed: %v", err)
				continue
			}
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err := os.WriteFile(h.config.GeoIPDBFile, body, 0644); err != nil {
					h.logger.warn("geoip write failed: %v", err)
					continue
				}
				h.geoip, _ = newGeoIPDB(h.config.GeoIPDBFile)
				h.logger.info("geoip updated successfully")
			} else {
				resp.Body.Close()
				h.logger.warn("geoip update: HTTP %d", resp.StatusCode)
			}
		}
	}
}

func (h *handler) extractJA3(req *http.Request) string {
	ua := req.UserAgent()
	maxLen := 64
	if len(ua) > maxLen {
		ua = ua[:maxLen]
	}
	return fmt.Sprintf("%s_%s_%s", req.Method, req.Proto, ua)
}

func (h *handler) serveAuditExport(w http.ResponseWriter, req *http.Request) {
	format := req.URL.Query().Get("format")
	if format != "csv" {
		format = "json"
	}

	entries := h.cache.GetAuditEntries(100)
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=hermes-guard-audit.csv")
		w.Write([]byte("timestamp,client_ip,method,path,reason,risk_score,host\n"))
		for _, entry := range entries {
			var m map[string]interface{}
			if json.Unmarshal([]byte(entry), &m) == nil {
				fmt.Fprintf(w, "%s,%s,%s,%s,%s,%.2f,%s\n",
					m["timestamp"], m["client_ip"], m["method"],
					m["path"], m["reason"], m["risk_score"], m["host"])
			}
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=hermes-guard-audit.json")
		w.Write([]byte("["))
		for i, entry := range entries {
			if i > 0 {
				w.Write([]byte(","))
			}
			w.Write([]byte(entry))
		}
		w.Write([]byte("]"))
	}
}

func (h *handler) isScheduledActive() (bool, string) {
	if len(h.config.ScheduledRules) == 0 {
		return false, ""
	}
	now := time.Now()
	currentMinutes := now.Hour()*60 + now.Minute()
	for _, rule := range h.config.ScheduledRules {
		parts := strings.Split(rule.CronExpr, "-")
		if len(parts) != 2 {
			continue
		}
		start := parseTimeToMinutes(parts[0])
		end := parseTimeToMinutes(parts[1])
		if currentMinutes >= start && currentMinutes <= end {
			return true, rule.Action
		}
	}
	return false, ""
}

func parseTimeToMinutes(s string) int {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ":")
	if len(parts) == 2 {
		h, _ := strconv.Atoi(parts[0])
		m, _ := strconv.Atoi(parts[1])
		return h*60 + m
	}
	v, _ := strconv.Atoi(s)
	return v
}
func (h *handler) recordHermesFeedback(hermesVerdict string, actualMatch bool) {
	if !h.config.HermesFeedbackEnabled {
		return
	}
	h.statsMu.Lock()
	h.hermesBlocks++
	if (hermesVerdict == "block" && actualMatch) || (hermesVerdict == "allow" && !actualMatch) {
		h.hermesCorrect++
	}
	h.statsMu.Unlock()
}

func (h *handler) serveFeedbackStats(w http.ResponseWriter) {
	h.statsMu.Lock()
	blocks := h.hermesBlocks
	correct := h.hermesCorrect
	h.statsMu.Unlock()
	accuracy := 0.0
	if blocks > 0 {
		accuracy = float64(correct) / float64(blocks) * 100
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"hermes_blocks":%d,"hermes_correct":%d,"accuracy":%.1f}`, blocks, correct, accuracy)
}

func (h *handler) serveSSE(w http.ResponseWriter, req *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx := req.Context()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			data := fmt.Sprintf(`{"requests":%d,"blocked":%d,"challenged":%d,"allowed":%d,"rate_hits":%d,"geoip":%d}`,
				h.readStat(&h.stats.requests), h.readStat(&h.stats.blocked),
				h.readStat(&h.stats.challenged), h.readStat(&h.stats.allowed),
				h.readStat(&h.stats.rateHits), h.readStat(&h.stats.geoipBlocks))
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (h *handler) Close() {
	h.cancel()
	if h.cache != nil {
		h.cache.Close()
	}
}

func (h *handler) isPathExcluded(path string) bool {
	for _, pattern := range h.excludedPaths {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

func (h *handler) isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, block := range h.privateNets {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ---- Logger ----

type logger struct {
	level LogLevel
	out   *os.File
}

func newLogger(level LogLevel) *logger {
	return &logger{level: level, out: os.Stderr}
}

func (l *logger) log(levelStr, format string, args ...interface{}) {
	now := time.Now().Format("2006/01/02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.out, "%s %s [hermes-guard] %s\n", now, levelStr, msg)
}

func (l *logger) debug(format string, args ...interface{}) {
	if l.level == LogDebug {
		l.log("DBG", format, args...)
	}
}

func (l *logger) info(format string, args ...interface{}) {
	if l.level == LogDebug || l.level == LogInfo {
		l.log("INF", format, args...)
	}
}

func (l *logger) warn(format string, args ...interface{}) {
	if l.level != LogError {
		l.log("WRN", format, args...)
	}
}

func (l *logger) errorf(format string, args ...interface{}) {
	l.log("ERR", format, args...)
}

// ---- Helpers ----

func maskEndpoint(s string) string {
	if s == "" {
		return "(none)"
	}
	u, err := url.Parse(s)
	if err != nil {
		return "(invalid)"
	}
	if u.User != nil {
		u.User = url.UserPassword("***", "***")
	}
	return u.String()
}

func clientID(req *http.Request) string {
	host, _, _ := net.SplitHostPort(req.RemoteAddr)
	if host == "" {
		return req.RemoteAddr
	}
	return host
}

func stripQueryParam(u *url.URL, param string) *url.URL {
	q := u.Query()
	q.Del(param)
	cleaned := *u
	cleaned.RawQuery = q.Encode()
	return &cleaned
}

// ---- Admin HTML (embedded) ----

var adminHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Hermes Guard — Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f0f0f;color:#e0e0e0;padding:32px;max-width:800px;margin:0 auto}
h1{font-size:24px;color:#fff;margin-bottom:24px;border-bottom:1px solid #333;padding-bottom:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:32px}
.stat{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:16px;text-align:center}
.stat .v{font-size:28px;font-weight:700;color:#f59e0b}
.stat .l{font-size:11px;color:#888;margin-top:4px}
.section{margin-bottom:24px}
.section h2{font-size:16px;color:#fff;margin-bottom:8px}
.section pre{background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:12px;font-size:12px;overflow-x:auto;color:#a0a0a0}
form{display:flex;gap:8px;margin-top:8px}
input{flex:1;padding:8px 12px;background:#1a1a1a;border:1px solid #333;border-radius:4px;color:#e0e0e0;font-size:13px}
button{padding:8px 20px;background:#f59e0b;border:none;border-radius:4px;color:#fff;font-weight:600;cursor:pointer;font-size:13px}
a{color:#f59e0b}
.refresh{display:block;margin-top:16px;font-size:12px;color:#666}
</style>
</head>
<body>
<h1>Hermes Guard Admin</h1>
<div class="stats">
<div class="stat"><div class="v" id="v-requests">{{REQUESTS}}</div><div class="l">Requests</div></div>
<div class="stat"><div class="v" id="v-allowed">{{ALLOWED}}</div><div class="l">Allowed</div></div>
<div class="stat"><div class="v" id="v-blocked">{{BLOCKED}}</div><div class="l">Blocked</div></div>
<div class="stat"><div class="v" id="v-challenged">{{CHALLENGED}}</div><div class="l">Challenged</div></div>
<div class="stat"><div class="v" id="v-rate">{{RATE_HITS}}</div><div class="l">Rate Hits</div></div>
<div class="stat"><div class="v" id="v-geoip">{{GEOIP}}</div><div class="l">GeoIP Blocks</div></div>
<div class="stat"><div class="v">{{LEAKS}}</div><div class="l">Resp Leaks</div></div>
<div class="stat"><div class="v">{{TURNSTILE}}</div><div class="l">Turnstile OK</div></div>
</div>
<div class="section">
<h2>Cache Stats</h2>
<pre>{{CACHE_STATS}}</pre>
</div>
<div class="section">
<h2>Unblock IP</h2>
<form method="POST" action="/.hermes-guard/admin/unblock">
<input name="secret" type="hidden" value="{{SECRET}}">
<input name="ip" placeholder="IP address to unblock" required>
<button>Unblock</button>
</form>
</div>
<div class="section">
<h2>Links</h2>
<p><a href="/.hermes-guard/metrics?secret={{SECRET}}">Prometheus metrics</a></p>
</div>
<div class="refresh">Live via SSE — <a href="/.hermes-guard/admin?secret={{SECRET}}">manual refresh</a></div>
<script>
var evtSource = new EventSource("/.hermes-guard/stream?secret={{SECRET}}");
evtSource.onmessage = function(e) {
    var d = JSON.parse(e.data);
    document.getElementById('v-requests').innerText = d.requests;
    document.getElementById('v-allowed').innerText = d.allowed;
    document.getElementById('v-blocked').innerText = d.blocked;
    document.getElementById('v-challenged').innerText = d.challenged;
    document.getElementById('v-rate').innerText = d.rate_hits;
    document.getElementById('v-geoip').innerText = d.geoip;
};
evtSource.onerror = function() { evtSource.close(); };
</script>
</body>
</html>`
