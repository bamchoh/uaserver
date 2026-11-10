// Package ua implements the OPC UA built-in data types, the UA Binary
// encoding and the structures/enumerations defined in Opc.Ua.Types.bsd.
package ua

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TypeID identifies one of the 25 OPC UA built-in types (Part 6, 5.1.2).
type TypeID byte

const (
	TypeNull            TypeID = 0
	TypeBoolean         TypeID = 1
	TypeSByte           TypeID = 2
	TypeByte            TypeID = 3
	TypeInt16           TypeID = 4
	TypeUInt16          TypeID = 5
	TypeInt32           TypeID = 6
	TypeUInt32          TypeID = 7
	TypeInt64           TypeID = 8
	TypeUInt64          TypeID = 9
	TypeFloat           TypeID = 10
	TypeDouble          TypeID = 11
	TypeString          TypeID = 12
	TypeDateTime        TypeID = 13
	TypeGuid            TypeID = 14
	TypeByteString      TypeID = 15
	TypeXmlElement      TypeID = 16
	TypeNodeId          TypeID = 17
	TypeExpandedNodeId  TypeID = 18
	TypeStatusCode      TypeID = 19
	TypeQualifiedName   TypeID = 20
	TypeLocalizedText   TypeID = 21
	TypeExtensionObject TypeID = 22
	TypeDataValue       TypeID = 23
	TypeVariant         TypeID = 24
	TypeDiagnosticInfo  TypeID = 25
)

var typeNames = [...]string{"Null", "Boolean", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32",
	"Int64", "UInt64", "Float", "Double", "String", "DateTime", "Guid", "ByteString", "XmlElement",
	"NodeId", "ExpandedNodeId", "StatusCode", "QualifiedName", "LocalizedText", "ExtensionObject",
	"DataValue", "Variant", "DiagnosticInfo"}

func (t TypeID) String() string {
	if int(t) < len(typeNames) {
		return typeNames[t]
	}
	return "TypeID(" + strconv.Itoa(int(t)) + ")"
}

// XmlElement is an XML fragment.
type XmlElement string

// StatusCode is an OPC UA status code.
type StatusCode uint32

func (s StatusCode) IsGood() bool      { return s&0xC0000000 == 0 }
func (s StatusCode) IsBad() bool       { return s&0x80000000 != 0 }
func (s StatusCode) IsUncertain() bool { return s&0x40000000 != 0 }

// Code returns the status code without the info bits.
func (s StatusCode) Code() StatusCode { return s & 0xFFFF0000 }

func (s StatusCode) Error() string { return s.String() }

func (s StatusCode) String() string {
	if n, ok := statusNames[s.Code()]; ok {
		return n
	}
	return fmt.Sprintf("StatusCode(0x%08X)", uint32(s))
}

// Guid is a 16 byte globally unique identifier, stored in UA binary wire order.
type Guid [16]byte

// NewGuid returns a random (version 4) Guid.
func NewGuid() Guid {
	var g Guid
	_, _ = rand.Read(g[:])
	g[7] = (g[7] & 0x0F) | 0x40
	g[8] = (g[8] & 0x3F) | 0x80
	return g
}

func (g Guid) String() string {
	return fmt.Sprintf("%08X-%04X-%04X-%s-%s",
		binary.LittleEndian.Uint32(g[0:4]), binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]),
		strings.ToUpper(hex.EncodeToString(g[8:10])), strings.ToUpper(hex.EncodeToString(g[10:16])))
}

// ParseGuid parses the canonical text form of a Guid.
func ParseGuid(s string) (Guid, error) {
	var g Guid
	s = strings.Trim(s, "{}")
	p := strings.Split(s, "-")
	if len(p) != 5 || len(p[0]) != 8 || len(p[1]) != 4 || len(p[2]) != 4 || len(p[3]) != 4 || len(p[4]) != 12 {
		return g, fmt.Errorf("ua: invalid guid %q", s)
	}
	d1, err1 := strconv.ParseUint(p[0], 16, 32)
	d2, err2 := strconv.ParseUint(p[1], 16, 16)
	d3, err3 := strconv.ParseUint(p[2], 16, 16)
	d4, err4 := hex.DecodeString(p[3] + p[4])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return g, fmt.Errorf("ua: invalid guid %q", s)
	}
	binary.LittleEndian.PutUint32(g[0:4], uint32(d1))
	binary.LittleEndian.PutUint16(g[4:6], uint16(d2))
	binary.LittleEndian.PutUint16(g[6:8], uint16(d3))
	copy(g[8:], d4)
	return g, nil
}

// QualifiedName is a name qualified by a namespace index.
type QualifiedName struct {
	NamespaceIndex uint16
	Name           string
}

// NewQualifiedName returns a QualifiedName.
func NewQualifiedName(ns uint16, name string) QualifiedName {
	return QualifiedName{NamespaceIndex: ns, Name: name}
}

func (q QualifiedName) String() string {
	if q.NamespaceIndex == 0 {
		return q.Name
	}
	return strconv.Itoa(int(q.NamespaceIndex)) + ":" + q.Name
}

// LocalizedText is human readable text with an optional locale.
type LocalizedText struct {
	Locale string
	Text   string
}

// NewLocalizedText returns a LocalizedText without locale.
func NewLocalizedText(text string) LocalizedText { return LocalizedText{Text: text} }

// DiagnosticInfo carries vendor specific diagnostic information.
type DiagnosticInfo struct {
	SymbolicID          *int32
	NamespaceURI        *int32
	Locale              *int32
	LocalizedText       *int32
	AdditionalInfo      *string
	InnerStatusCode     *StatusCode
	InnerDiagnosticInfo *DiagnosticInfo
}

// DataValue is a value with status and timestamps.
type DataValue struct {
	Value             Variant
	Status            StatusCode
	SourceTimestamp   time.Time
	SourcePicoseconds uint16
	ServerTimestamp   time.Time
	ServerPicoseconds uint16
}

// NewDataValue returns a good DataValue holding v.
func NewDataValue(v Variant) DataValue { return DataValue{Value: v} }

// ExtensionObject wraps an encoded structure.
//
// TypeID is the binary encoding id (or data type id) of the body. If the body
// type is known, Value holds the decoded Structure; otherwise Value holds the raw
// body ([]byte for binary bodies, XmlElement for XML bodies).
type ExtensionObject struct {
	TypeID ExpandedNodeId
	Value  any
}

// NewExtensionObject wraps a structure into an ExtensionObject.
func NewExtensionObject(s Structure) ExtensionObject {
	if s == nil {
		return ExtensionObject{}
	}
	return ExtensionObject{TypeID: NewExpandedNodeId(s.BinaryEncodingID()), Value: s}
}

// IsNull reports whether the extension object has no body.
func (e ExtensionObject) IsNull() bool { return e.Value == nil }

// Structure is implemented by every generated structure type.
type Structure interface {
	// DataTypeID is the NodeId of the DataType node.
	DataTypeID() NodeId
	// BinaryEncodingID is the NodeId of the DefaultBinary encoding.
	BinaryEncodingID() NodeId
	Encode(e *Encoder)
	Decode(d *Decoder)
}

// Request is implemented by every service request.
type Request interface {
	Structure
	Header() *RequestHeader
}

// Response is implemented by every service response (including ServiceFault).
type Response interface {
	Structure
	Header() *ResponseHeader
}

var structFactories = map[NodeId]func() Structure{}
var structByDataType = map[NodeId]func() Structure{}

// RegisterStructure registers a structure factory under its encoding and data type ids.
func RegisterStructure(f func() Structure) {
	s := f()
	structFactories[s.BinaryEncodingID()] = f
	structByDataType[s.DataTypeID()] = f
}

// NewStructureByEncodingID creates an empty structure for an encoding (or data type) id.
func NewStructureByEncodingID(id NodeId) Structure {
	if f, ok := structFactories[id]; ok {
		return f()
	}
	if f, ok := structByDataType[id]; ok {
		return f()
	}
	return nil
}

// LookupStructureByDataType creates an empty structure for a data type id.
func LookupStructureByDataType(id NodeId) Structure {
	if f, ok := structByDataType[id]; ok {
		return f()
	}
	return nil
}

// Time conversion (DateTime is 100ns ticks since 1601-01-01 UTC).
const ticksTo1970 = 116444736000000000

var maxDateTime = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// TimeToTicks converts a time to a UA DateTime value.
func TimeToTicks(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	if t.After(maxDateTime) {
		return 0x7FFFFFFFFFFFFFFF
	}
	if t.Year() < 1601 {
		return 0
	}
	sec := t.Unix()
	return (sec*10000000 + int64(t.Nanosecond()/100)) + ticksTo1970
}

// TicksToTime converts a UA DateTime value to a time.
func TicksToTime(v int64) time.Time {
	if v <= 0 || v == 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	v -= ticksTo1970
	sec := v / 10000000
	ns := (v % 10000000) * 100
	if ns < 0 {
		sec--
		ns += 1e9
	}
	return time.Unix(sec, ns).UTC()
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
