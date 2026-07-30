package traefik_hermes_guard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Compile-time interface check.
var _ Detector = (*detector)(nil)

type patternsFile struct {
	Version    int                 `json:"version"`
	Category   string              `json:"category,omitempty"`
	Patterns   []patternsFileEntry `json:"patterns"`
	UserAgents []string            `json:"malicious_user_agents"`
	Scoring    *riskScoringFile    `json:"risk_scoring,omitempty"`
}

type patternsFileEntry struct {
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

type riskScoringFile struct {
	URLMatch       float64 `json:"url_match_weight"`
	BodyMatch      float64 `json:"body_match_weight"`
	HeaderAnomaly  float64 `json:"header_anomaly_weight"`
	MaliciousUA    float64 `json:"malicious_ua_weight"`
	SuspiciousXFF  float64 `json:"suspicious_xff_weight"`
	MethodOverride float64 `json:"method_override_weight"`
}

type detector struct {
	patterns      []*regexp.Regexp
	patternCats   []string
	maliciousUAs  []string
	scoring       RiskScoring
	maxBody       int64
	logger        *logger
	patternStrs   []string
	patternsPath  string
	collDir       string
}

func newDetector(patternStrs []string, patternsFilePath string, collectionsDir string, maxBodySize int64, logr *logger) *detector {
	d := &detector{
		maxBody:      maxBodySize,
		scoring:      defaultRiskScoring(),
		logger:       logr,
		patternStrs:  patternStrs,
		patternsPath: patternsFilePath,
		collDir:      collectionsDir,
	}
	d.load()
	return d
}

func (d *detector) load() {
	d.patterns = nil
	d.patternCats = nil
	d.maliciousUAs = nil

	// Auto-load all JSON files from collections directory
	if d.collDir != "" {
		if entries, err := os.ReadDir(d.collDir); err == nil {
			total := 0
			loaded := 0
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
					continue
				}
				path := d.collDir + "/" + e.Name()
				pf, err := loadPatternsFile(path)
				if err != nil {
					d.logger.warn("failed to load collection %q: %v", e.Name(), err)
					continue
				}
				for _, entry := range pf.Patterns {
					re, reErr := regexp.Compile(entry.Pattern)
					if reErr != nil {
						d.logger.warn("invalid pattern %q: %v", entry.Name, reErr)
						continue
					}
					d.patterns = append(d.patterns, re)
					d.patternCats = append(d.patternCats, pf.Category)
				}
				total += len(pf.Patterns)
				loaded++
			}
			if total > 0 {
				d.logger.info("loaded %d patterns from %d collections in %s", total, loaded, d.collDir)
				return
			}
		}
	}

	// Fallback: single patterns file
	if d.patternsPath != "" {
		if pf, err := loadPatternsFile(d.patternsPath); err == nil {
			for _, entry := range pf.Patterns {
				re, reErr := regexp.Compile(entry.Pattern)
				if reErr != nil {
					d.logger.warn("invalid pattern %q: %v", entry.Name, reErr)
					continue
				}
				d.patterns = append(d.patterns, re)
				d.patternCats = append(d.patternCats, entry.Category)
			}
			if len(pf.UserAgents) > 0 {
				d.maliciousUAs = pf.UserAgents
			}
			if pf.Scoring != nil {
				d.scoring = RiskScoring{
					URLMatchWeight:       pf.Scoring.URLMatch,
					BodyMatchWeight:      pf.Scoring.BodyMatch,
					HeaderAnomalyWeight:  pf.Scoring.HeaderAnomaly,
					MaliciousUAWeight:    pf.Scoring.MaliciousUA,
					SuspiciousXFFWeight:  pf.Scoring.SuspiciousXFF,
					MethodOverrideWeight: pf.Scoring.MethodOverride,
				}
			}
			d.logger.info("loaded %d patterns + %d UAs from %s",
				len(d.patterns), len(d.maliciousUAs), d.patternsPath)
			return
		}
		d.logger.warn("failed to load patterns file %s — using inline", d.patternsPath)
	}

	for _, p := range d.patternStrs {
		re, err := regexp.Compile(p)
		if err != nil {
			d.logger.warn("invalid inline pattern: %s", p)
			continue
		}
		d.patterns = append(d.patterns, re)
		d.patternCats = append(d.patternCats, "")
	}

	if len(d.maliciousUAs) == 0 {
		d.maliciousUAs = defaultMaliciousUAs()
	}

	d.logger.info("using %d inline patterns", len(d.patterns))
}

func (d *detector) Reload() error {
	d.logger.info("hot-reloading patterns...")
	d.load()
	return nil
}

func (d *detector) Analyze(req *http.Request) *DetectionResult {
	result := &DetectionResult{}

	d.checkURL(result, req)
	d.checkHeaders(result, req)

	if result.RiskScore > 0 || (req.Body != nil && d.maxBody > 0) {
		d.checkBody(result, req)
	}

	result.IsSuspicious = result.RiskScore >= 0.5
	result.RiskScore = clampScore(result.RiskScore)

	if result.RiskScore > 0 {
		d.logger.debug("detection: path=%s risk=%.2f patterns=%v",
			req.URL.RequestURI(), result.RiskScore, result.MatchedPatterns)
	}

	return result
}

func (d *detector) checkURL(result *DetectionResult, req *http.Request) {
	input := req.URL.Path
	if req.URL.RawQuery != "" {
		input += "?" + req.URL.RawQuery
	}

	decoded, _ := url.QueryUnescape(input)
	if decoded == input {
		decoded = decodePercent(input)
	}

	matched := 0
	for i, pattern := range d.patterns {
		if pattern.MatchString(input) || (decoded != input && pattern.MatchString(decoded)) {
			result.MatchedPatterns = append(result.MatchedPatterns, pattern.String())
			if result.Category == "" && i < len(d.patternCats) {
				result.Category = d.patternCats[i]
			}
			matched++
		}
	}
	if matched > 0 {
		d.logger.debug("URL match: input=%q matched=%d risk=%.2f",
			input, matched, d.scoring.URLMatchWeight*float64(matched))
		result.RiskScore += d.scoring.URLMatchWeight * float64(matched)
		if result.RiskScore < d.scoring.URLMatchWeight {
			result.RiskScore = d.scoring.URLMatchWeight
		}
	}
}

func (d *detector) checkHeaders(result *DetectionResult, req *http.Request) {
	ua := req.UserAgent()
	if d.isMaliciousUA(ua) {
		result.MatchedPatterns = append(result.MatchedPatterns, "malicious_user_agent")
		result.RiskScore += d.scoring.MaliciousUAWeight
		result.Reason = "Known malicious User-Agent: " + ua
		return
	}

	xForwardedFor := req.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" && strings.Count(xForwardedFor, ",") > 5 {
		result.MatchedPatterns = append(result.MatchedPatterns, "suspicious_x_forwarded_for")
		result.RiskScore += d.scoring.SuspiciousXFFWeight
	}

	if req.Header.Get("X-Http-Method-Override") != "" ||
		req.Header.Get("X-Method-Override") != "" {
		result.MatchedPatterns = append(result.MatchedPatterns, "method_override_header")
		result.RiskScore += d.scoring.MethodOverrideWeight
	}

	if req.Header.Get("Content-Type") == "" && req.ContentLength > 0 {
		result.RiskScore += d.scoring.HeaderAnomalyWeight
	}
}

func (d *detector) checkBody(result *DetectionResult, req *http.Request) {
	if req.Body == nil || d.maxBody <= 0 {
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, d.maxBody))
	if err != nil {
		return
	}
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if len(bodyBytes) == 0 {
		return
	}

	result.BodyBytes = bodyBytes

	bodyStr := string(bodyBytes)
	matched := 0
	for i, pattern := range d.patterns {
		if pattern.MatchString(bodyStr) {
			result.MatchedPatterns = append(result.MatchedPatterns, pattern.String())
			if result.Category == "" && i < len(d.patternCats) {
				result.Category = d.patternCats[i]
			}
			matched++
		}
	}
	if matched > 0 {
		result.RiskScore += d.scoring.BodyMatchWeight * float64(matched)
		if result.RiskScore < d.scoring.BodyMatchWeight {
			result.RiskScore = d.scoring.BodyMatchWeight
		}
	}
}

func (d *detector) isMaliciousUA(ua string) bool {
	lower := strings.ToLower(ua)
	for _, mua := range d.maliciousUAs {
		if strings.Contains(lower, mua) {
			return true
		}
	}
	return false
}

func loadPatternsFile(path string) (*patternsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pf patternsFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, err
	}

	if pf.Version != 1 {
		// silently accept other versions
	}

	return &pf, nil
}

func clampScore(score float64) float64 {
	if score > 1.0 {
		return 1.0
	}
	return score
}

func defaultMaliciousUAs() []string {
	return []string{
		"sqlmap", "nikto", "nessus", "nmap", "acunetix",
		"burpsuite", "w3af", "zmeu", "gobuster", "dirbuster",
		"hydra", "medusa", "metasploit", "openvas",
		"zgrab", "masscan", "whatweb", "wpscan",
	}
}

func decodePercent(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			high := unhex(s[i+1])
			low := unhex(s[i+2])
			if high >= 0 && low >= 0 {
				out.WriteByte(byte(high<<4 | low))
				i += 2
				continue
			}
		}
		if s[i] == '+' {
			out.WriteByte(' ')
			continue
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

func unhex(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c - 'a' + 10)
	case 'A' <= c && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}
