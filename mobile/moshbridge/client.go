// Package moshbridge exposes the small, gomobile-compatible surface used by
// GateShell's Apple clients. The protocol, encryption, retransmission, and
// terminal-state synchronization remain implemented in Go.
package moshbridge

import (
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	mosh "github.com/unixshells/mosh-go"
)

// Client is a thread-safe handle to one encrypted Mosh session.
type Client struct {
	mu     sync.RWMutex
	client *mosh.Client
	conn   *roamingUDPConn
}

// Dial opens an encrypted UDP session. A wildcard-bound datagram socket is
// intentionally used so Darwin can select a new source interface after a
// Wi-Fi/cellular route change while preserving Mosh transport state.
func Dial(host string, port int, key string) (*Client, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("mosh: invalid UDP port %d", port)
	}
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, fmt.Errorf("mosh: resolving host: %w", err)
	}
	conn, err := newRoamingUDPConn(remote)
	if err != nil {
		return nil, fmt.Errorf("mosh: opening UDP socket: %w", err)
	}
	rawKey, err := decodeKey(key)
	if err != nil {
		conn.Close()
		return nil, err
	}
	ocb, err := mosh.NewOCB(rawKey)
	if err != nil {
		conn.Close()
		return nil, err
	}
	inner, err := mosh.DialConn(conn, ocb)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Client{client: inner, conn: conn}, nil
}

func decodeKey(key string) ([]byte, error) {
	for len(key)%4 != 0 {
		key += "="
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 16 {
		return nil, fmt.Errorf("mosh: invalid session key")
	}
	return raw, nil
}

// Send forwards terminal input to the synchronized Go transport.
func (c *Client) Send(data []byte) error {
	inner, err := c.active()
	if err != nil {
		return err
	}
	inner.Send(data)
	return nil
}

// Receive returns terminal output, or empty when the timeout expires.
//
// Returning empty rather than nil keeps the Go-side contract honest, but note
// it does NOT stop the Swift caller from throwing: gomobile maps an empty
// []byte to a nil NSData just like a nil slice, and Swift imports
// `-receive:error:` under Objective-C's "nil result means failure"
// convention, so an idle poll still surfaces there as a synthesized
// _GenericObjCError (verified on-device). Callers therefore must not treat a
// thrown error as a dead session -- use IsClosed for that.
func (c *Client) Receive(timeoutMillis int64) ([]byte, error) {
	inner, err := c.active()
	if err != nil {
		return nil, err
	}
	if timeoutMillis < 1 {
		timeoutMillis = 1
	}
	if timeoutMillis > 30_000 {
		timeoutMillis = 30_000
	}
	out := inner.Recv(time.Duration(timeoutMillis) * time.Millisecond)
	if out == nil {
		return []byte{}, nil
	}
	return out, nil
}

// Resize updates the remote PTY dimensions.
func (c *Client) Resize(cols, rows int) error {
	if cols < 1 || cols > 65535 || rows < 1 || rows > 65535 {
		return fmt.Errorf("mosh: invalid terminal size %dx%d", cols, rows)
	}
	inner, err := c.active()
	if err != nil {
		return err
	}
	inner.Resize(uint16(cols), uint16(rows))
	return nil
}

// IsClosed reports whether this session has been shut down.
//
// The Swift receive loop needs it to tell an idle poll from a dead session.
// gomobile emits Receive as `-receive:error:`, which Swift imports under
// Objective-C's "nil means failure" convention, so a quiet poll can surface
// at the call site as a thrown error indistinguishable from a real failure.
// Without this the loop treats its first idle moment as a disconnect.
func (c *Client) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client == nil
}

// HasReceivedPacket reports whether the encrypted server has answered at
// least once. The Apple app uses this bounded handshake to distinguish a
// working Mosh path from blocked UDP before replacing its SSH terminal.
func (c *Client) HasReceivedPacket() bool {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	return conn != nil && conn.received.Load()
}

// LastPacketAgeMillis powers the Apple client's connection-quality badge.
// A negative value means no authenticated packet has arrived yet.
func (c *Client) LastPacketAgeMillis() int64 {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return -1
	}
	receivedAt := conn.lastReceived.Load()
	if receivedAt == 0 {
		return -1
	}
	return max(0, time.Now().UnixMilli()-receivedAt)
}

// PredictiveEcho returns a short, visibly underlined local prediction for
// printable typing. Control input, invalid UTF-8, and paste-sized chunks remain
// server-authoritative. The next absolute framebuffer diff confirms or replaces
// the prediction.
func PredictiveEcho(input []byte) []byte {
	if len(input) == 0 || len(input) > 32 || !utf8.Valid(input) {
		return nil
	}
	for _, r := range string(input) {
		if unicode.IsControl(r) {
			return nil
		}
	}
	output := make([]byte, 0, len(input)+10)
	output = append(output, "\x1b[4m"...)
	output = append(output, input...)
	output = append(output, "\x1b[24m"...)
	return output
}

// Close is idempotent.
func (c *Client) Close() {
	c.mu.Lock()
	inner := c.client
	c.client = nil
	c.conn = nil
	c.mu.Unlock()
	if inner != nil {
		inner.Close()
	}
}

func (c *Client) active() (*mosh.Client, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.client == nil {
		return nil, fmt.Errorf("mosh: session is closed")
	}
	return c.client, nil
}

type roamingUDPConn struct {
	conn         *net.UDPConn
	remote       *net.UDPAddr
	received     atomic.Bool
	lastReceived atomic.Int64
}

func newRoamingUDPConn(remote *net.UDPAddr) (*roamingUDPConn, error) {
	network := "udp4"
	localIP := net.IPv4zero
	if remote.IP.To4() == nil {
		network = "udp6"
		localIP = net.IPv6unspecified
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		return nil, err
	}
	return &roamingUDPConn{conn: conn, remote: remote}, nil
}

func (c *roamingUDPConn) Read(buffer []byte) (int, error) {
	for {
		n, source, err := c.conn.ReadFromUDP(buffer)
		if err != nil {
			return 0, err
		}
		if source.Port == c.remote.Port && source.IP.Equal(c.remote.IP) {
			c.received.Store(true)
			c.lastReceived.Store(time.Now().UnixMilli())
			return n, nil
		}
	}
}

func (c *roamingUDPConn) Write(data []byte) (int, error) {
	return c.conn.WriteToUDP(data, c.remote)
}

func (c *roamingUDPConn) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

func (c *roamingUDPConn) Close() error { return c.conn.Close() }
