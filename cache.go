package traefik_hermes_guard

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const (
	blockedKeyPrefix   = "hg:blocked:"
	whitelistKey       = "hg:whitelist"
	verdictPrefix      = "hg:verdict:"
	challengeKeyPrefix = "hg:challenge:"
	turnstilePrefix    = "hg:turnstile:"
	rateLimitPrefix    = "hg:ratelimit:"
	auditKey           = "hg:audit"
	auditMaxEntries    = 1000
	defaultBlockTTL    = 3600
	turnstileMax       = 5
	turnstileWindow    = 60
	memCacheMaxEntries = 10000
	memCleanupInterval = 30 * time.Second
)

type cacheLayer struct {
	client      *respClient
	mem         *memCache
	blockTTL    int
	memFallback bool
	stats       cacheStats
	logger      *logger
	mu          sync.Mutex
}

type memEntry struct {
	expiresAt time.Time
	value     interface{}
}

type memCache struct {
	mu   sync.RWMutex
	data map[string]*memEntry
}

type cacheStats struct {
	blocks    int64
	rateHits  int64
	memReads  int64
	redisErrs int64
}

func newCacheLayer(addr, password string, db, blockTTL int, logr *logger) *cacheLayer {
	if blockTTL <= 0 {
		blockTTL = defaultBlockTTL
	}
	cl := &cacheLayer{
		blockTTL: blockTTL,
		logger:   logr,
		mem: &memCache{
			data: make(map[string]*memEntry),
		},
	}

	if addr != "" {
		cl.client = newRESPClient(addr, password, db)
		if err := cl.client.cmd("PING"); err != nil {
			logr.warn("Redis unavailable (%s): %v — using in-memory cache fallback", addr, err)
			cl.client = nil
			cl.memFallback = true
		} else {
			logr.info("Redis connected: %s", addr)
		}
	}

	go cl.memCleanupLoop()
	return cl
}

func (c *cacheLayer) memCleanupLoop() {
	ticker := time.NewTicker(memCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		c.mem.mu.Lock()
		now := time.Now()
		for k, v := range c.mem.data {
			if now.After(v.expiresAt) {
				delete(c.mem.data, k)
			}
		}
		c.mem.mu.Unlock()
	}
}

func (c *cacheLayer) memGet(key string) (interface{}, bool) {
	c.mu.Lock()
	c.stats.memReads++
	c.mu.Unlock()

	c.mem.mu.RLock()
	defer c.mem.mu.RUnlock()
	e, ok := c.mem.data[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.value, true
}

func (c *cacheLayer) memSet(key string, value interface{}, ttl int) {
	c.mem.mu.Lock()
	defer c.mem.mu.Unlock()
	if len(c.mem.data) >= memCacheMaxEntries {
		return
	}
	c.mem.data[key] = &memEntry{
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
		value:     value,
	}
}

func (c *cacheLayer) memDel(key string) {
	c.mem.mu.Lock()
	delete(c.mem.data, key)
	c.mem.mu.Unlock()
}

func (c *cacheLayer) blockedKey(ip string) string {
	return blockedKeyPrefix + ip
}

func (c *cacheLayer) IsBlocked(ip string) (bool, error) {
	if c.memFallback {
		_, ok := c.memGet("blk:" + ip)
		return ok, nil
	}
	if c.client == nil {
		return false, nil
	}
	_, err := c.client.cmdString("GET", c.blockedKey(ip))
	if err != nil {
		if err.Error() == "redis: nil" {
			return false, nil
		}
		c.mu.Lock()
		c.stats.redisErrs++
		c.mu.Unlock()
		return false, nil
	}
	return true, nil
}

func (c *cacheLayer) IsWhitelisted(ip string) (bool, error) {
	if c.memFallback {
		_, ok := c.memGet("wl:" + ip)
		return ok, nil
	}
	if c.client == nil {
		return false, nil
	}
	result, err := c.client.cmdInt("SISMEMBER", whitelistKey, ip)
	if err != nil {
		c.mu.Lock()
		c.stats.redisErrs++
		c.mu.Unlock()
		return false, nil
	}
	return result == 1, nil
}

func (c *cacheLayer) BlockIP(ip string, ttl int) error {
	c.mu.Lock()
	c.stats.blocks++
	c.mu.Unlock()

	if ttl <= 0 {
		ttl = c.blockTTL
	}
	if c.memFallback || c.client == nil {
		c.memSet("blk:"+ip, true, ttl)
		return nil
	}
	return c.client.cmd("SETEX", c.blockedKey(ip), fmt.Sprintf("%d", ttl), "1")
}

func (c *cacheLayer) UnblockIP(ip string) error {
	c.memDel("blk:" + ip)
	if c.memFallback || c.client == nil {
		return nil
	}
	return c.client.cmd("DEL", c.blockedKey(ip))
}

func (c *cacheLayer) UnwhitelistIP(ip string) error {
	c.memDel("wl:" + ip)
	if c.memFallback || c.client == nil {
		return nil
	}
	return c.client.cmd("SREM", whitelistKey, ip)
}

func (c *cacheLayer) WhitelistIP(ip string) error {
	if c.memFallback || c.client == nil {
		c.memSet("wl:"+ip, true, c.blockTTL)
		return nil
	}
	return c.client.cmd("SADD", whitelistKey, ip)
}

func (c *cacheLayer) GetVerdict(key string) (*CacheEntry, error) {
	if c.memFallback {
		v, ok := c.memGet("vd:" + key)
		if !ok {
			return nil, nil
		}
		entry, _ := v.(*CacheEntry)
		return entry, nil
	}
	if c.client == nil {
		return nil, nil
	}
	redisKey := verdictPrefix + key
	data, err := c.client.cmdString("GET", redisKey)
	if err != nil {
		if err.Error() == "redis: nil" {
			return nil, nil
		}
		return nil, nil
	}
	if data == "" {
		return nil, nil
	}
	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (c *cacheLayer) SetVerdict(key string, entry *CacheEntry) error {
	if c.memFallback || c.client == nil {
		c.memSet("vd:"+key, entry, c.blockTTL)
		return nil
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	redisKey := verdictPrefix + key
	ttl := int(time.Until(entry.ExpiresAt).Seconds())
	if ttl <= 0 {
		ttl = c.blockTTL
	}
	return c.client.cmd("SETEX", redisKey, fmt.Sprintf("%d", ttl), string(data))
}

func (c *cacheLayer) Ping() error {
	if c.memFallback || c.client == nil {
		return nil
	}
	_, err := c.client.cmdString("PING")
	return err
}

func (c *cacheLayer) Close() {
	if c.client != nil {
		c.client.close()
	}
}

func (c *cacheLayer) RateLimitCheck(ip string, maxReqs, windowSec int) (bool, error) {
	if c.client == nil && !c.memFallback {
		return true, nil
	}

	if c.memFallback {
		v, _ := c.memGet("rl:" + ip)
		cnt := int64(0)
		if v != nil {
			cnt, _ = v.(int64)
		}
		if cnt >= int64(maxReqs) {
			return false, nil
		}
		c.memSet("rl:"+ip, cnt+1, windowSec)
		return true, nil
	}

	key := rateLimitPrefix + ip
	result, err := c.client.cmdInt("INCR", key)
	if err != nil {
		c.mu.Lock()
		c.stats.redisErrs++
		c.mu.Unlock()
		return true, nil
	}
	if result == 1 {
		_ = c.client.cmd("EXPIRE", key, fmt.Sprintf("%d", windowSec))
	}
	if result > int64(maxReqs) {
		c.mu.Lock()
		c.stats.rateHits++
		c.mu.Unlock()
		return false, nil
	}
	return true, nil
}

func (c *cacheLayer) CheckTurnstileRateLimit(ip string) (bool, error) {
	if c.client == nil && !c.memFallback {
		return true, nil
	}

	if c.memFallback {
		v, _ := c.memGet("tr:" + ip)
		cnt := int64(0)
		if v != nil {
			cnt, _ = v.(int64)
		}
		if cnt >= turnstileMax {
			return false, nil
		}
		c.memSet("tr:"+ip, cnt+1, turnstileWindow)
		return true, nil
	}

	key := turnstilePrefix + ip
	result, err := c.client.cmdInt("INCR", key)
	if err != nil {
		return true, nil
	}
	if result == 1 {
		_ = c.client.cmd("EXPIRE", key, fmt.Sprintf("%d", turnstileWindow))
	}
	return result <= turnstileMax, nil
}

func (c *cacheLayer) RecordTurnstileSuccess(ip string, ttl int) error {
	return c.WhitelistIP(ip)
}

func (c *cacheLayer) ResetTurnstileCounter(ip string) error {
	if c.memFallback || c.client == nil {
		c.memDel("tr:" + ip)
		return nil
	}
	return c.client.cmd("DEL", turnstilePrefix+ip)
}

func (c *cacheLayer) MarkChallenge(ip string, ttl int) error {
	if c.memFallback || c.client == nil {
		c.memSet("ch:"+ip, true, ttl)
		return nil
	}
	return c.client.cmd("SETEX", challengeKeyPrefix+ip, fmt.Sprintf("%d", ttl), "1")
}

func (c *cacheLayer) IsChallenged(ip string) bool {
	if c.memFallback || c.client == nil {
		_, ok := c.memGet("ch:" + ip)
		return ok
	}
	_, err := c.client.cmdString("GET", challengeKeyPrefix+ip)
	return err == nil
}

func (c *cacheLayer) ClearChallenge(ip string) error {
	c.memDel("ch:" + ip)
	if c.memFallback || c.client == nil {
		return nil
	}
	return c.client.cmd("DEL", challengeKeyPrefix+ip)
}

func (c *cacheLayer) Stats() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	fb := int64(0)
	if c.memFallback {
		fb = 1
	}
	return map[string]int64{
		"blocks":     c.stats.blocks,
		"rate_hits":  c.stats.rateHits,
		"mem_reads":  c.stats.memReads,
		"redis_errs": c.stats.redisErrs,
		"fallback":   fb,
	}
}

func (c *cacheLayer) BlockedCount() int {
	if c.memFallback || c.client == nil {
		c.mem.mu.RLock()
		defer c.mem.mu.RUnlock()
		cnt := 0
		now := time.Now()
		for k, v := range c.mem.data {
			if len(k) > 4 && k[:4] == "blk:" && now.Before(v.expiresAt) {
				cnt++
			}
		}
		return cnt
	}
	return -1
}

// l1EvalScript atomically checks blocklist, whitelist, and verdict.
const l1EvalScript = `
local blocked_key = KEYS[1]
local whitelist_key = KEYS[2]
local verdict_key = KEYS[3]
local ip = ARGV[1]

local blocked = redis.call('EXISTS', blocked_key)
local whitelisted = redis.call('SISMEMBER', whitelist_key, ip)
local verdict = redis.call('GET', verdict_key)

return {blocked, whitelisted, verdict or ''}
`

func (c *cacheLayer) EvalL1(ip string) (bool, bool, *CacheEntry, error) {
	if c.memFallback || c.client == nil {
		blocked, _ := c.IsBlocked(ip)
		whitelisted, _ := c.IsWhitelisted(ip)
		entry, _ := c.GetVerdict(ip + ":latest")
		return blocked, whitelisted, entry, nil
	}

	keys := []string{
		c.blockedKey(ip),
		whitelistKey,
		verdictPrefix + ip + ":latest",
	}
	args := []string{ip}

	resp, err := c.client.eval(l1EvalScript, keys, args)
	if err != nil {
		return false, false, nil, err
	}

	arr, ok := resp.([]interface{})
	if !ok || len(arr) < 3 {
		return false, false, nil, nil
	}

	blockedVal := int64(0)
	if arr[0] != nil {
		blockedVal, _ = arr[0].(int64)
	}
	whitelistVal := int64(0)
	if arr[1] != nil {
		whitelistVal, _ = arr[1].(int64)
	}
	verdictData := ""
	if arr[2] != nil {
		verdictData, _ = arr[2].(string)
	}

	var entry *CacheEntry
	if verdictData != "" {
		json.Unmarshal([]byte(verdictData), &entry)
	}

	return blockedVal == 1, whitelistVal == 1, entry, nil
}

func (c *cacheLayer) AuditLog(entry string) error {
	if c.memFallback || c.client == nil {
		return nil
	}
	_ = c.client.cmd("LPUSH", auditKey, entry)
	_ = c.client.cmd("LTRIM", auditKey, fmt.Sprintf("%d", auditMaxEntries-1))
	return nil
}
