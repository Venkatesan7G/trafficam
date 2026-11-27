package localapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/store"
)

// Client talks to the watcher service over the local socket / pipe.
type Client struct {
	Addr string
	hc   *http.Client
}

// NewClient returns a client for the socket or pipe at addr.
func NewClient(addr string) *Client {
	return newClientWith(addr, func(ctx context.Context) (net.Conn, error) { return dial(ctx, addr) })
}

func newClientWith(addr string, d func(ctx context.Context) (net.Conn, error)) *Client {
	tr := &http.Transport{
		DialContext:           func(ctx context.Context, _, _ string) (net.Conn, error) { return d(ctx) },
		MaxIdleConns:          2,
		IdleConnTimeout:       time.Minute,
		ResponseHeaderTimeout: 40 * time.Second, // longer than the server's long-poll
		DisableCompression:    true,
		Proxy:                 nil, // never send local API traffic to a proxy
	}
	return &Client{Addr: addr, hc: &http.Client{Transport: tr, Timeout: 45 * time.Second}}
}

// The host name is ignored: every request goes to the socket.
const base = "http://trafficam.local"

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("trafficam service: %s: %s", resp.Status, b)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

// Status asks for the watcher's status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	return s, c.get(ctx, "/v1/status", nil, &s)
}

// Alerts lists stored alerts.
func (c *Client) Alerts(ctx context.Context, q store.AlertQuery) ([]store.Alert, error) {
	v := url.Values{}
	if q.AfterID > 0 {
		v.Set("after", strconv.FormatInt(q.AfterID, 10))
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	if !q.Since.IsZero() {
		v.Set("since", strconv.FormatInt(q.Since.Unix(), 10))
	}
	if q.State != "" {
		v.Set("state", string(q.State))
	}
	if q.Newest {
		v.Set("newest", "1")
	}
	var l AlertList
	return l.Alerts, c.get(ctx, "/v1/alerts", v, &l)
}

// Wait returns alerts with ID > after, waiting up to ~25 s for one to arrive.
func (c *Client) Wait(ctx context.Context, after int64) ([]store.Alert, error) {
	var l AlertList
	return l.Alerts, c.get(ctx, "/v1/alerts/wait", url.Values{"after": {strconv.FormatInt(after, 10)}}, &l)
}
