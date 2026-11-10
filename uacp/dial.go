package uacp

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/bamchoh/uastack/ua"
)

// ClientLimits are the limits a client offers in its Hello message.
type ClientLimits struct {
	ReceiveBufferSize uint32
	SendBufferSize    uint32
	MaxMessageSize    uint32 // 0 = no limit
	MaxChunkCount     uint32 // 0 = no limit
}

// DefaultClientLimits are the limits used when a field of ClientLimits is 0.
var DefaultClientLimits = ClientLimits{
	ReceiveBufferSize: 65535,
	SendBufferSize:    65535,
	MaxMessageSize:    16 * 1024 * 1024,
	MaxChunkCount:     4096,
}

// Error is an ERR message received from the server.
type Error struct {
	Code   ua.StatusCode
	Reason string
}

func (e *Error) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("uacp: server error %s", e.Code)
	}
	return fmt.Sprintf("uacp: server error %s: %s", e.Code, e.Reason)
}

// Unwrap returns the status code, so errors.Is(err, ua.StatusBadXxx) works.
func (e *Error) Unwrap() error { return e.Code }

// ParseError decodes the body of an ERR chunk.
func ParseError(ch *Chunk) *Error {
	d := ua.NewDecoder(ch.Data[HeaderSize:])
	e := &Error{Code: d.ReadStatusCode(), Reason: d.ReadString()}
	if d.Err() != nil && e.Code == 0 {
		e.Code = ua.StatusBadTcpMessageTypeInvalid
	}
	return e
}

// HostPort returns the host:port of an opc.tcp URL (the port defaults to 4840).
func HostPort(endpointURL string) (string, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return "", fmt.Errorf("uacp: invalid endpoint url %q: %w", endpointURL, err)
	}
	if u.Scheme != "opc.tcp" {
		return "", fmt.Errorf("uacp: unsupported scheme %q (only opc.tcp is supported)", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("uacp: endpoint url %q has no host", endpointURL)
	}
	port := u.Port()
	if port == "" {
		port = "4840"
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// Dial connects to an opc.tcp endpoint and performs the client side of the
// Hello/Acknowledge handshake.
func Dial(ctx context.Context, endpointURL string, limits ClientLimits) (*Conn, error) {
	addr, err := HostPort(endpointURL)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	uc, err := Handshake(ctx, c, endpointURL, limits)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return uc, nil
}

// Handshake performs the client side of the Hello/Acknowledge handshake on an
// established connection.
func Handshake(ctx context.Context, c net.Conn, endpointURL string, limits ClientLimits) (*Conn, error) {
	if limits.ReceiveBufferSize == 0 {
		limits.ReceiveBufferSize = DefaultClientLimits.ReceiveBufferSize
	}
	if limits.SendBufferSize == 0 {
		limits.SendBufferSize = DefaultClientLimits.SendBufferSize
	}
	if limits.ReceiveBufferSize < MinBufferSize || limits.SendBufferSize < MinBufferSize {
		return nil, fmt.Errorf("uacp: buffer sizes must be at least %d bytes", MinBufferSize)
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	defer c.SetDeadline(time.Time{})
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()

	e := ua.NewEncoder(64 + len(endpointURL))
	e.WriteRaw([]byte("HELF"))
	e.WriteUint32(0)
	e.WriteUint32(0) // protocol version
	e.WriteUint32(limits.ReceiveBufferSize)
	e.WriteUint32(limits.SendBufferSize)
	e.WriteUint32(limits.MaxMessageSize)
	e.WriteUint32(limits.MaxChunkCount)
	e.WriteString(endpointURL)
	b := e.Bytes()
	putSize(b)
	if _, err := c.Write(b); err != nil {
		return nil, ctxErr(ctx, err)
	}

	// Until the server answers, accept chunks up to our receive buffer size.
	uc := &Conn{Conn: c, ReceiveBufferSize: limits.ReceiveBufferSize, client: true}
	ch, err := uc.ReadChunk()
	if err != nil {
		return nil, ctxErr(ctx, err)
	}
	switch ch.Type {
	case MsgAcknowledge:
	case MsgError:
		return nil, ParseError(ch)
	default:
		return nil, fmt.Errorf("uacp: expected ACK, got %s", ch.Type)
	}
	d := ua.NewDecoder(ch.Data[HeaderSize:])
	ack := Acknowledge{
		ProtocolVersion:   d.ReadUint32(),
		ReceiveBufferSize: d.ReadUint32(),
		SendBufferSize:    d.ReadUint32(),
		MaxMessageSize:    d.ReadUint32(),
		MaxChunkCount:     d.ReadUint32(),
	}
	if d.Err() != nil {
		return nil, fmt.Errorf("uacp: malformed ACK")
	}
	if ack.ReceiveBufferSize < MinBufferSize || ack.SendBufferSize < MinBufferSize {
		return nil, fmt.Errorf("uacp: server buffer sizes too small")
	}
	// The server sends chunks no larger than its send buffer, which must not
	// exceed our receive buffer; we must not send more than it can receive.
	uc.ReceiveBufferSize = min(limits.ReceiveBufferSize, ack.SendBufferSize)
	uc.SendBufferSize = min(limits.SendBufferSize, ack.ReceiveBufferSize)
	uc.MaxMessageSize = limits.MaxMessageSize
	uc.MaxChunkCount = limits.MaxChunkCount
	uc.PeerMaxMessage = ack.MaxMessageSize
	uc.PeerMaxChunks = ack.MaxChunkCount
	uc.EndpointURL = endpointURL
	return uc, nil
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func putSize(b []byte) {
	n := uint32(len(b))
	b[4], b[5], b[6], b[7] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
}
