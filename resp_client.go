package traefik_hermes_guard

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	errNil       = errors.New("redis: nil")
	errConnReset = errors.New("redis: connection reset")
	errTimeout   = errors.New("redis: timeout")
)

const (
	defaultTimeout    = 2 * time.Second
	poolSize          = 8
	redisDialTimeout  = 3 * time.Second
	redisReadTimeout  = 2 * time.Second
	redisWriteTimeout = 2 * time.Second
	maxRetries        = 3
	baseRetryBackoff  = 50 * time.Millisecond
)

const (
	respSimpleString = '+'
	respError        = '-'
	respInteger      = ':'
	respBulkString   = '$'
	respArray        = '*'
)

type respClient struct {
	mu          sync.Mutex
	addr        string
	password    string
	db          int
	pool        chan *respConn
	timeout     time.Duration
	closed      bool
	useTLS      bool
	tlsSkipVerify bool
}

type respConn struct {
	conn   net.Conn
	reader *bufio.Reader
}

func newRESPClient(addr, password string, db int, tlsEnabled bool, tlsSkipVerify bool) *respClient {
	c := &respClient{
		addr:           addr,
		password:       password,
		db:             db,
		pool:           make(chan *respConn, poolSize),
		timeout:        defaultTimeout,
		useTLS:         tlsEnabled,
		tlsSkipVerify:  tlsSkipVerify,
	}
	return c
}

func (c *respClient) getConn() (*respConn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("redis: client closed")
	}
	c.mu.Unlock()

	select {
	case rc := <-c.pool:
		return rc, nil
	default:
		return c.dial()
	}
}

func (c *respClient) putConn(rc *respConn) {
	if rc == nil {
		return
	}
	select {
	case c.pool <- rc:
	default:
		rc.conn.Close()
	}
}

func (c *respClient) discardConn(rc *respConn) {
	if rc != nil {
		rc.conn.Close()
	}
}

func (c *respClient) dial() (*respConn, error) {
	var conn net.Conn
	var err error

	if c.useTLS {
		tlsCfg := &tls.Config{InsecureSkipVerify: c.tlsSkipVerify}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: redisDialTimeout}, "tcp", c.addr, tlsCfg)
	} else {
		conn, err = net.DialTimeout("tcp", c.addr, redisDialTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("redis dial %s: %w", c.addr, err)
	}

	rc := &respConn{
		conn:   conn,
		reader: bufio.NewReaderSize(conn, 4096),
	}

	if c.password != "" {
		if err := c.exec(rc, "AUTH", c.password); err != nil {
			conn.Close()
			return nil, fmt.Errorf("redis AUTH: %w", err)
		}
	}
	if c.db > 0 {
		if err := c.exec(rc, "SELECT", strconv.Itoa(c.db)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("redis SELECT %d: %w", c.db, err)
		}
	}

	return rc, nil
}

func (c *respClient) writeCmd(rc *respConn, args ...string) error {
	rc.conn.SetWriteDeadline(time.Now().Add(redisWriteTimeout))

	var sb strings.Builder
	sb.WriteByte(respArray)
	sb.WriteString(strconv.Itoa(len(args)))
	sb.WriteString("\r\n")
	for _, arg := range args {
		sb.WriteByte(respBulkString)
		sb.WriteString(strconv.Itoa(len(arg)))
		sb.WriteString("\r\n")
		sb.WriteString(arg)
		sb.WriteString("\r\n")
	}

	_, err := rc.conn.Write([]byte(sb.String()))
	return err
}

func (c *respClient) readResponse(rc *respConn) (interface{}, error) {
	rc.conn.SetReadDeadline(time.Now().Add(redisReadTimeout))

	line, err := rc.reader.ReadBytes('\n')
	if err != nil {
		if isNetTimeout(err) {
			return nil, errTimeout
		}
		return nil, errConnReset
	}
	if len(line) < 3 {
		return nil, fmt.Errorf("redis: short response")
	}
	line = line[:len(line)-2]

	switch line[0] {
	case respSimpleString:
		return string(line[1:]), nil
	case respError:
		return nil, fmt.Errorf("redis: %s", string(line[1:]))
	case respInteger:
		return strconv.ParseInt(string(line[1:]), 10, 64)
	case respBulkString:
		length, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return nil, fmt.Errorf("redis: invalid bulk length: %s", string(line[1:]))
		}
		if length < 0 {
			return nil, errNil
		}
		buf := make([]byte, length+2)
		_, err = io.ReadFull(rc.reader, buf)
		if err != nil {
			if isNetTimeout(err) {
				return nil, errTimeout
			}
			return nil, errConnReset
		}
		return string(buf[:length]), nil
	case respArray:
		count, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return nil, fmt.Errorf("redis: invalid array length: %s", string(line[1:]))
		}
		if count < 0 {
			return nil, errNil
		}
		result := make([]interface{}, count)
		for i := 0; i < count; i++ {
			result[i], err = c.readResponse(rc)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	default:
		return nil, fmt.Errorf("redis: unknown response type: %c", line[0])
	}
}

func (c *respClient) exec(rc *respConn, args ...string) error {
	if err := c.writeCmd(rc, args...); err != nil {
		return errConnReset
	}
	_, err := c.readResponse(rc)
	return err
}

func (c *respClient) cmd(args ...string) error {
	return c.cmdWithRetry(args, func(rc *respConn) error {
		return c.exec(rc, args...)
	})
}

func (c *respClient) cmdString(args ...string) (string, error) {
	var result string
	err := c.cmdWithRetry(args, func(rc *respConn) error {
		if err := c.writeCmd(rc, args...); err != nil {
			return errConnReset
		}
		resp, err := c.readResponse(rc)
		if err != nil {
			return err
		}
		if resp == nil {
			return errNil
		}
		s, ok := resp.(string)
		if !ok {
			return fmt.Errorf("redis: expected string, got %T", resp)
		}
		result = s
		return nil
	})
	return result, err
}

func (c *respClient) cmdInt(args ...string) (int64, error) {
	var result int64
	err := c.cmdWithRetry(args, func(rc *respConn) error {
		if err := c.writeCmd(rc, args...); err != nil {
			return errConnReset
		}
		resp, err := c.readResponse(rc)
		if err != nil {
			return err
		}
		v, ok := resp.(int64)
		if !ok {
			return fmt.Errorf("redis: expected int64, got %T", resp)
		}
		result = v
		return nil
	})
	return result, err
}

func (c *respClient) cmdWithRetry(args []string, fn func(*respConn) error) error {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		rc, err := c.getConn()
		if err != nil {
			return err
		}

		err = fn(rc)
		if err == nil {
			c.putConn(rc)
			return nil
		}

		if isRetryable(err) {
			c.discardConn(rc)
		} else {
			c.putConn(rc)
			return err
		}

		lastErr = err
		backoff := baseRetryBackoff * time.Duration(1<<attempt)
		jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
		time.Sleep(backoff + jitter)
	}
	return fmt.Errorf("redis: retries exhausted: %w", lastErr)
}

// Eval runs a Lua script with keys and args, returning the raw Redis response.
func (c *respClient) eval(script string, keys, args []string) (interface{}, error) {
	return c.evalWithRetry(script, keys, args)
}

func (c *respClient) evalWithRetry(script string, keys, args []string) (interface{}, error) {
	var result interface{}
	fullArgs := append([]string{"EVAL", script, fmt.Sprintf("%d", len(keys))}, keys...)
	fullArgs = append(fullArgs, args...)

	err := c.cmdWithRetry(fullArgs, func(rc *respConn) error {
		if e := c.writeCmd(rc, fullArgs...); e != nil {
			return errConnReset
		}
		resp, e := c.readResponse(rc)
		if e != nil {
			return e
		}
		result = resp
		return nil
	})
	return result, err
}

func (c *respClient) evalString(script string, keys, args []string) (string, error) {
	resp, err := c.eval(script, keys, args)
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", errNil
	}
	s, ok := resp.(string)
	if !ok {
		return "", fmt.Errorf("redis eval: expected string, got %T", resp)
	}
	return s, nil
}

func (c *respClient) evalInt(script string, keys, args []string) (int64, error) {
	resp, err := c.eval(script, keys, args)
	if err != nil {
		return 0, err
	}
	v, ok := resp.(int64)
	if !ok {
		return 0, fmt.Errorf("redis eval: expected int64, got %T", resp)
	}
	return v, nil
}

func (c *respClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	close(c.pool)
	for rc := range c.pool {
		rc.conn.Close()
	}
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errConnReset) || errors.Is(err, errTimeout) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "LOADING") ||
		strings.Contains(msg, "BUSY") ||
		strings.Contains(msg, "READONLY") ||
		strings.Contains(msg, "TRYAGAIN")
}

func isNetTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
