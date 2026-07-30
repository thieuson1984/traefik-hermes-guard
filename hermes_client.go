package traefik_hermes_guard

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	hermesTimeout = 10 * time.Second
	healthPath    = "/health"
)

type hermesClient struct {
	endpoint       *url.URL
	token          string
	blockNotifyURL string
	blockSecret    string
	httpClient     *http.Client
	logger         *logger
}

func newHermesClient(endpoint, token, blockNotifyURL, blockSecret string, tlsInsecure bool, tlsCAFile string, logr *logger) *hermesClient {
	var parsed *url.URL
	if endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil {
			logr.warn("invalid hermes endpoint %q: %v", endpoint, err)
		} else {
			parsed = u
		}
	}

	transport := &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     60 * time.Second,
	}

	if tlsInsecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	} else if tlsCAFile != "" {
		caCert, err := os.ReadFile(tlsCAFile)
		if err != nil {
			logr.warn("failed to read TLS CA file %s: %v", tlsCAFile, err)
		} else {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			transport.TLSClientConfig = &tls.Config{RootCAs: caCertPool}
		}
	}

	return &hermesClient{
		endpoint:       parsed,
		token:          token,
		blockNotifyURL: blockNotifyURL,
		blockSecret:    blockSecret,
		logger:         logr,
		httpClient: &http.Client{
			Timeout:   hermesTimeout,
			Transport: transport,
		},
	}
}

func (h *hermesClient) resolve(path string) string {
	if h.endpoint == nil {
		return ""
	}
	u := *h.endpoint
	u.Path, _ = url.JoinPath(u.Path, path)
	return u.String()
}

func (h *hermesClient) NotifyBlock(event WebhookEvent) {
	go h.notifyBlockSync(event)
}

func (h *hermesClient) NotifyUnblock(clientIP, secret string) {
	if h.endpoint == nil {
		return
	}
	target := h.blockNotifyURL
	if target == "" {
		target = "/webhooks/traefik-block-events"
	}

	u := *h.endpoint
	u.Path = target

	payload := map[string]string{
		"ip":     clientIP,
		"rule":   "unblock",
		"time":   time.Now().UTC().Format(time.RFC3339),
		"reason": "manually unblocked",
		"method": "API",
		"service": "unblock",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	go func() {
		req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if h.blockSecret != "" {
			mac := hmac.New(sha256.New, []byte(h.blockSecret))
			mac.Write(data)
			sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			req.Header.Set("X-Hub-Signature-256", sig)
		}
		resp, err := h.httpClient.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
	}()
}

func (h *hermesClient) notifyBlockSync(event WebhookEvent) {
	if h.endpoint == nil {
		return
	}

	// Webhook path takes priority if configured
	targetPath := h.blockNotifyURL
	if targetPath == "" {
		targetPath = "/webhooks/traefik-block-events"
	}

	u := *h.endpoint
	u.Path = targetPath
	target := u.String()

	payload := map[string]string{
		"ip":      event.ClientIP,
		"host":    event.Host,
		"rule":    event.Reason,
		"time":    event.Timestamp,
		"reason":  event.Reason,
		"method":  event.Method,
		"service": event.Path,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		h.logger.warn("hermes notify marshal: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		h.logger.warn("hermes notify request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if h.blockSecret != "" {
		mac := hmac.New(sha256.New, []byte(h.blockSecret))
		mac.Write(data)
		sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		h.logger.warn("hermes notify failed: %v", err)
		return
	}
	resp.Body.Close()

	h.logger.info("hermes notified: ip=%s path=%s reason=%s", event.ClientIP, event.Path, event.Reason)
}

func (h *hermesClient) HealthCheck(ctx context.Context) error {
	target := h.resolve(healthPath)
	if target == "" {
		return fmt.Errorf("hermes: no endpoint configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("hermes health: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hermes unhealthy: HTTP %d", resp.StatusCode)
	}

	return nil
}
