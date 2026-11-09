// Package uacp implements the OPC UA Connection Protocol (Part 6, 7.1): the
// message framing used by opc.tcp and the Hello/Acknowledge handshake.
package uacp

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/bamchoh/uaserver/ua"
)

// Message types.
const (
	MsgHello        = "HEL"
	MsgAcknowledge  = "ACK"
	MsgError        = "ERR"
	MsgReverseHello = "RHE"
	MsgOpen         = "OPN"
	MsgMessage      = "MSG"
	MsgClose        = "CLO"
)

// Chunk types.
const (
	ChunkFinal        = 'F'
	ChunkIntermediate = 'C'
	ChunkAbort        = 'A'
)

// HeaderSize is the size of the message header.
const HeaderSize = 8

// MinBufferSize is the minimum buffer size allowed by the specification.
const MinBufferSize = 8192

// Hello is the first message sent by a client.
type Hello struct {
	ProtocolVersion   uint32
	ReceiveBufferSize uint32
	SendBufferSize    uint32
	MaxMessageSize    uint32
	MaxChunkCount     uint32
	EndpointURL       string
}

// Acknowledge is the response to a Hello message.
type Acknowledge struct {
	ProtocolVersion   uint32
	ReceiveBufferSize uint32
	SendBufferSize    uint32
	MaxMessageSize    uint32
	MaxChunkCount     uint32
}

// Chunk is a single raw message chunk including its header.
type Chunk struct {
	Type      string // HEL, ACK, ERR, OPN, MSG, CLO
	ChunkType byte   // F, C, A
	Data      []byte // the complete chunk including the 8 byte header
}

// Conn wraps a network connection that speaks UA-CP.
type Conn struct {
	net.Conn
	// Negotiated limits (from the server's point of view).
	ReceiveBufferSize uint32
	SendBufferSize    uint32
	MaxMessageSize    uint32 // max size of a message we accept
	MaxChunkCount     uint32 // max chunks of a message we accept
	PeerMaxMessage    uint32 // max size of a message the peer accepts (0 = no limit)
	PeerMaxChunks     uint32 // max chunks the peer accepts (0 = no limit)
	EndpointURL       string
}

// ServerLimits are the limits a server offers during the handshake.
type ServerLimits struct {
	ReceiveBufferSize uint32
	SendBufferSize    uint32
	MaxMessageSize    uint32
	MaxChunkCount     uint32
}

// Accept performs the server side of the Hello/Acknowledge handshake.
func Accept(c net.Conn, limits ServerLimits, timeout time.Duration) (*Conn, error) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})

	uc := &Conn{Conn: c, ReceiveBufferSize: MinBufferSize, SendBufferSize: MinBufferSize}
	ch, err := uc.ReadChunk()
	if err != nil {
		return nil, err
	}
	if ch.Type != MsgHello || ch.ChunkType != ChunkFinal {
		uc.SendError(ua.StatusBadTcpMessageTypeInvalid, "expected HEL")
		return nil, fmt.Errorf("uacp: expected HEL, got %s", ch.Type)
	}
	d := ua.NewDecoder(ch.Data[HeaderSize:])
	h := Hello{
		ProtocolVersion:   d.ReadUint32(),
		ReceiveBufferSize: d.ReadUint32(),
		SendBufferSize:    d.ReadUint32(),
		MaxMessageSize:    d.ReadUint32(),
		MaxChunkCount:     d.ReadUint32(),
		EndpointURL:       d.ReadString(),
	}
	if d.Err() != nil {
		uc.SendError(ua.StatusBadTcpMessageTypeInvalid, "malformed HEL")
		return nil, d.Err()
	}
	if len(h.EndpointURL) > 4096 {
		uc.SendError(ua.StatusBadTcpEndpointUrlInvalid, "endpoint url too long")
		return nil, fmt.Errorf("uacp: endpoint url too long")
	}
	if h.ReceiveBufferSize < MinBufferSize || h.SendBufferSize < MinBufferSize {
		uc.SendError(ua.StatusBadConnectionRejected, "buffer size too small")
		return nil, fmt.Errorf("uacp: client buffer too small")
	}
	// Our receive buffer must not exceed the client's send buffer and vice versa.
	uc.ReceiveBufferSize = min(limits.ReceiveBufferSize, h.SendBufferSize)
	uc.SendBufferSize = min(limits.SendBufferSize, h.ReceiveBufferSize)
	uc.MaxMessageSize = limits.MaxMessageSize
	uc.MaxChunkCount = limits.MaxChunkCount
	uc.PeerMaxMessage = h.MaxMessageSize
	uc.PeerMaxChunks = h.MaxChunkCount
	uc.EndpointURL = h.EndpointURL

	e := ua.NewEncoder(28)
	e.WriteRaw([]byte("ACKF"))
	e.WriteUint32(28)
	e.WriteUint32(0) // protocol version
	e.WriteUint32(uc.ReceiveBufferSize)
	e.WriteUint32(uc.SendBufferSize)
	e.WriteUint32(uc.MaxMessageSize)
	e.WriteUint32(uc.MaxChunkCount)
	if _, err := c.Write(e.Bytes()); err != nil {
		return nil, err
	}
	return uc, nil
}

// ReadChunk reads one chunk from the connection.
func (c *Conn) ReadChunk() (*Chunk, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(hdr[4:])
	if size < HeaderSize || size > c.ReceiveBufferSize {
		c.SendError(ua.StatusBadTcpMessageTooLarge, "chunk size invalid")
		return nil, fmt.Errorf("uacp: invalid chunk size %d", size)
	}
	buf := make([]byte, size)
	copy(buf, hdr[:])
	if _, err := io.ReadFull(c.Conn, buf[HeaderSize:]); err != nil {
		return nil, err
	}
	ch := &Chunk{Type: string(hdr[:3]), ChunkType: hdr[3], Data: buf}
	switch ch.Type {
	case MsgHello, MsgAcknowledge, MsgError, MsgOpen, MsgMessage, MsgClose, MsgReverseHello:
	default:
		c.SendError(ua.StatusBadTcpMessageTypeInvalid, "unknown message type")
		return nil, fmt.Errorf("uacp: unknown message type %q", ch.Type)
	}
	switch ch.ChunkType {
	case ChunkFinal, ChunkIntermediate, ChunkAbort:
	default:
		c.SendError(ua.StatusBadTcpMessageTypeInvalid, "unknown chunk type")
		return nil, fmt.Errorf("uacp: unknown chunk type %q", ch.ChunkType)
	}
	return ch, nil
}

// SendError sends an ERR message. Errors while sending are ignored.
func (c *Conn) SendError(code ua.StatusCode, reason string) {
	e := ua.NewEncoder(64)
	e.WriteRaw([]byte("ERRF"))
	e.WriteUint32(0)
	e.WriteStatusCode(code)
	e.WriteString(reason)
	b := e.Bytes()
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	_ = c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Conn.Write(b)
	_ = c.Conn.SetWriteDeadline(time.Time{})
}
