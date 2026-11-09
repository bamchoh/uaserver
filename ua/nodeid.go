package ua

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// IDType is the kind of identifier held by a NodeId.
type IDType byte

const (
	IDNumeric    IDType = 0
	IDString     IDType = 1
	IDGuid       IDType = 2
	IDByteString IDType = 3
)

// NodeId identifies a node in a server address space.
//
// NodeId is comparable and can be used as a map key. For ByteString
// identifiers the bytes are stored in Str.
type NodeId struct {
	Namespace uint16
	Type      IDType
	Numeric   uint32
	Str       string
	Guid      Guid
}

// NewNumericNodeId returns a numeric NodeId.
func NewNumericNodeId(ns uint16, id uint32) NodeId {
	return NodeId{Namespace: ns, Type: IDNumeric, Numeric: id}
}

// NewStringNodeId returns a string NodeId.
func NewStringNodeId(ns uint16, id string) NodeId {
	return NodeId{Namespace: ns, Type: IDString, Str: id}
}

// NewGuidNodeId returns a guid NodeId.
func NewGuidNodeId(ns uint16, id Guid) NodeId {
	return NodeId{Namespace: ns, Type: IDGuid, Guid: id}
}

// NewByteStringNodeId returns an opaque NodeId.
func NewByteStringNodeId(ns uint16, id []byte) NodeId {
	return NodeId{Namespace: ns, Type: IDByteString, Str: string(id)}
}

// IsNull reports whether n is the null NodeId.
func (n NodeId) IsNull() bool {
	if n.Namespace != 0 {
		return false
	}
	switch n.Type {
	case IDNumeric:
		return n.Numeric == 0
	case IDString, IDByteString:
		return n.Str == ""
	case IDGuid:
		return n.Guid == Guid{}
	}
	return false
}

// Bytes returns the identifier of a ByteString NodeId.
func (n NodeId) Bytes() []byte { return []byte(n.Str) }

func (n NodeId) String() string {
	var sb strings.Builder
	if n.Namespace != 0 {
		sb.WriteString("ns=")
		sb.WriteString(strconv.Itoa(int(n.Namespace)))
		sb.WriteByte(';')
	}
	n.writeIdentifier(&sb)
	return sb.String()
}

func (n NodeId) writeIdentifier(sb *strings.Builder) {
	switch n.Type {
	case IDNumeric:
		sb.WriteString("i=")
		sb.WriteString(strconv.FormatUint(uint64(n.Numeric), 10))
	case IDString:
		sb.WriteString("s=")
		sb.WriteString(n.Str)
	case IDGuid:
		sb.WriteString("g=")
		sb.WriteString(n.Guid.String())
	case IDByteString:
		sb.WriteString("b=")
		sb.WriteString(base64.StdEncoding.EncodeToString([]byte(n.Str)))
	}
}

// ParseNodeId parses the standard text form of a NodeId ("ns=1;s=Foo", "i=85", ...).
func ParseNodeId(s string) (NodeId, error) {
	var n NodeId
	rest := s
	if strings.HasPrefix(rest, "ns=") {
		i := strings.IndexByte(rest, ';')
		if i < 0 {
			return n, fmt.Errorf("ua: invalid node id %q", s)
		}
		ns, err := strconv.ParseUint(rest[3:i], 10, 16)
		if err != nil {
			return n, fmt.Errorf("ua: invalid namespace in %q", s)
		}
		n.Namespace = uint16(ns)
		rest = rest[i+1:]
	}
	if len(rest) < 2 || rest[1] != '=' {
		return n, fmt.Errorf("ua: invalid node id %q", s)
	}
	v := rest[2:]
	switch rest[0] {
	case 'i':
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return n, fmt.Errorf("ua: invalid numeric id in %q", s)
		}
		n.Type, n.Numeric = IDNumeric, uint32(id)
	case 's':
		n.Type, n.Str = IDString, v
	case 'g':
		g, err := ParseGuid(v)
		if err != nil {
			return n, err
		}
		n.Type, n.Guid = IDGuid, g
	case 'b':
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return n, fmt.Errorf("ua: invalid opaque id in %q", s)
		}
		n.Type, n.Str = IDByteString, string(b)
	default:
		return n, fmt.Errorf("ua: invalid node id %q", s)
	}
	return n, nil
}

// MustParseNodeId is like ParseNodeId but panics on error.
func MustParseNodeId(s string) NodeId {
	n, err := ParseNodeId(s)
	if err != nil {
		panic(err)
	}
	return n
}

// ExpandedNodeId is a NodeId that may refer to a namespace by URI and to another server.
type ExpandedNodeId struct {
	NodeId       NodeId
	NamespaceURI string
	ServerIndex  uint32
}

// NewExpandedNodeId wraps a local NodeId.
func NewExpandedNodeId(n NodeId) ExpandedNodeId { return ExpandedNodeId{NodeId: n} }

// IsNull reports whether e is null.
func (e ExpandedNodeId) IsNull() bool {
	return e.NodeId.IsNull() && e.NamespaceURI == "" && e.ServerIndex == 0
}

// IsLocal reports whether the id refers to the local server.
func (e ExpandedNodeId) IsLocal() bool { return e.ServerIndex == 0 }

func (e ExpandedNodeId) String() string {
	var sb strings.Builder
	if e.ServerIndex != 0 {
		sb.WriteString("svr=")
		sb.WriteString(strconv.FormatUint(uint64(e.ServerIndex), 10))
		sb.WriteByte(';')
	}
	if e.NamespaceURI != "" {
		sb.WriteString("nsu=")
		sb.WriteString(url.PathEscape(e.NamespaceURI))
		sb.WriteByte(';')
		e.NodeId.writeIdentifier(&sb)
		return sb.String()
	}
	sb.WriteString(e.NodeId.String())
	return sb.String()
}

// ParseExpandedNodeId parses the text form of an ExpandedNodeId.
func ParseExpandedNodeId(s string) (ExpandedNodeId, error) {
	var e ExpandedNodeId
	rest := s
	if strings.HasPrefix(rest, "svr=") {
		i := strings.IndexByte(rest, ';')
		if i < 0 {
			return e, fmt.Errorf("ua: invalid expanded node id %q", s)
		}
		v, err := strconv.ParseUint(rest[4:i], 10, 32)
		if err != nil {
			return e, err
		}
		e.ServerIndex = uint32(v)
		rest = rest[i+1:]
	}
	if strings.HasPrefix(rest, "nsu=") {
		i := strings.IndexByte(rest, ';')
		if i < 0 {
			return e, fmt.Errorf("ua: invalid expanded node id %q", s)
		}
		u, err := url.PathUnescape(rest[4:i])
		if err != nil {
			u = rest[4:i]
		}
		e.NamespaceURI = u
		rest = rest[i+1:]
	}
	n, err := ParseNodeId(rest)
	if err != nil {
		return e, err
	}
	e.NodeId = n
	return e, nil
}
