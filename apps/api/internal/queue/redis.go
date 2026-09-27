package queue

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	addr     string
	password string
}

func New(raw string) (*Client, error) {
	u, e := url.Parse(raw)
	if e != nil {
		return nil, e
	}
	host := u.Host
	if host == "" {
		host = "127.0.0.1:6379"
	}
	if !strings.Contains(host, ":") {
		host += ":6379"
	}
	password := ""
	if u.User != nil {
		password, _ = u.User.Password()
	}
	return &Client{addr: host, password: password}, nil
}
func (c *Client) PING(ctx context.Context) error { _, e := c.do(ctx, []string{"PING"}); return e }
func (c *Client) SetNX(ctx context.Context, key, val string, ttl time.Duration) (bool, error) {
	r, e := c.do(ctx, []string{"SET", key, val, "NX", "PX", strconv.FormatInt(ttl.Milliseconds(), 10)})
	return r == "OK", e
}
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	return c.do(ctx, []string{"GET", key})
}
func (c *Client) Set(ctx context.Context, key, val string, ttl time.Duration) error {
	_, e := c.do(ctx, []string{"SET", key, val, "EX", strconv.Itoa(int(ttl.Seconds()))})
	return e
}
func (c *Client) do(ctx context.Context, args []string) (string, error) {
	d := net.Dialer{}
	conn, e := d.DialContext(ctx, "tcp", c.addr)
	if e != nil {
		return "", e
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}
	if c.password != "" {
		_, e = writeResp(conn, []string{"AUTH", c.password})
		if e != nil {
			return "", e
		}
		if _, e = readResp(bufio.NewReader(conn)); e != nil {
			return "", e
		}
	}
	if _, e = writeResp(conn, args); e != nil {
		return "", e
	}
	return readResp(bufio.NewReader(conn))
}
func writeResp(w net.Conn, args []string) (int, error) {
	b := fmt.Sprintf("*%d\r\n", len(args))
	for _, a := range args {
		b += fmt.Sprintf("$%d\r\n%s\r\n", len(a), a)
	}
	return w.Write([]byte(b))
}
func readResp(r *bufio.Reader) (string, error) {
	p, e := r.ReadByte()
	if e != nil {
		return "", e
	}
	switch p {
	case '+', '-', ';', ':':
		line, e := r.ReadString('\n')
		if e != nil {
			return "", e
		}
		if p == '-' {
			return "", errors.New(strings.TrimSpace(line))
		}
		return strings.TrimSpace(line), nil
	case '$':
		line, e := r.ReadString('\n')
		if e != nil {
			return "", e
		}
		n, _ := strconv.Atoi(strings.TrimSpace(line))
		if n < 0 {
			return "", nil
		}
		buf := make([]byte, n+2)
		if _, e = r.Read(buf); e != nil {
			return "", e
		}
		return string(buf[:n]), nil
	default:
		return "", fmt.Errorf("unsupported redis reply %q", p)
	}
}
