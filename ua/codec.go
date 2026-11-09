package ua

import (
	"encoding/binary"
	"errors"
	"math"
	"time"
)

// Limits applied while decoding to protect against malicious input.
const (
	MaxStringLength = 16 * 1024 * 1024
	MaxArrayLength  = 1024 * 1024
	MaxNestingDepth = 64
)

// ErrDecoding is returned when a message cannot be decoded.
var ErrDecoding = errors.New("ua: decoding error")

// Encoder writes values in UA Binary encoding.
type Encoder struct {
	buf []byte
}

// NewEncoder returns an encoder with an initial capacity.
func NewEncoder(capacity int) *Encoder { return &Encoder{buf: make([]byte, 0, capacity)} }

// Bytes returns the encoded bytes.
func (e *Encoder) Bytes() []byte { return e.buf }

// Len returns the number of encoded bytes.
func (e *Encoder) Len() int { return len(e.buf) }

// Reset clears the buffer.
func (e *Encoder) Reset() { e.buf = e.buf[:0] }

// WriteRaw appends raw bytes.
func (e *Encoder) WriteRaw(b []byte) { e.buf = append(e.buf, b...) }

func (e *Encoder) WriteBool(v bool) {
	if v {
		e.buf = append(e.buf, 1)
	} else {
		e.buf = append(e.buf, 0)
	}
}
func (e *Encoder) WriteInt8(v int8)   { e.buf = append(e.buf, byte(v)) }
func (e *Encoder) WriteUint8(v byte)  { e.buf = append(e.buf, v) }
func (e *Encoder) WriteInt16(v int16) { e.buf = binary.LittleEndian.AppendUint16(e.buf, uint16(v)) }
func (e *Encoder) WriteUint16(v uint16) {
	e.buf = binary.LittleEndian.AppendUint16(e.buf, v)
}
func (e *Encoder) WriteInt32(v int32) { e.buf = binary.LittleEndian.AppendUint32(e.buf, uint32(v)) }
func (e *Encoder) WriteUint32(v uint32) {
	e.buf = binary.LittleEndian.AppendUint32(e.buf, v)
}
func (e *Encoder) WriteInt64(v int64) { e.buf = binary.LittleEndian.AppendUint64(e.buf, uint64(v)) }
func (e *Encoder) WriteUint64(v uint64) {
	e.buf = binary.LittleEndian.AppendUint64(e.buf, v)
}
func (e *Encoder) WriteFloat32(v float32) { e.WriteUint32(math.Float32bits(v)) }
func (e *Encoder) WriteFloat64(v float64) { e.WriteUint64(math.Float64bits(v)) }

// WriteString writes a String; the empty string is encoded as null.
func (e *Encoder) WriteString(v string) {
	if v == "" {
		e.WriteInt32(-1)
		return
	}
	e.WriteInt32(int32(len(v)))
	e.buf = append(e.buf, v...)
}

// WriteByteString writes a ByteString; a nil slice is encoded as null.
func (e *Encoder) WriteByteString(v []byte) {
	if v == nil {
		e.WriteInt32(-1)
		return
	}
	e.WriteInt32(int32(len(v)))
	e.buf = append(e.buf, v...)
}

func (e *Encoder) WriteXmlElement(v XmlElement) { e.WriteString(string(v)) }
func (e *Encoder) WriteDateTime(v time.Time)    { e.WriteInt64(TimeToTicks(v)) }
func (e *Encoder) WriteGuid(v Guid)             { e.buf = append(e.buf, v[:]...) }
func (e *Encoder) WriteStatusCode(v StatusCode) { e.WriteUint32(uint32(v)) }

// WriteArrayLength writes the length prefix of an array (-1 for nil).
func (e *Encoder) WriteArrayLength(n int, isNil bool) {
	if isNil {
		e.WriteInt32(-1)
		return
	}
	e.WriteInt32(int32(n))
}

func (e *Encoder) writeNodeIdMask(n NodeId, flags byte) {
	switch n.Type {
	case IDNumeric:
		switch {
		case n.Namespace == 0 && n.Numeric <= 0xFF:
			e.buf = append(e.buf, 0x00|flags, byte(n.Numeric))
		case n.Namespace <= 0xFF && n.Numeric <= 0xFFFF:
			e.buf = append(e.buf, 0x01|flags, byte(n.Namespace))
			e.WriteUint16(uint16(n.Numeric))
		default:
			e.buf = append(e.buf, 0x02|flags)
			e.WriteUint16(n.Namespace)
			e.WriteUint32(n.Numeric)
		}
	case IDString:
		e.buf = append(e.buf, 0x03|flags)
		e.WriteUint16(n.Namespace)
		e.WriteString(n.Str)
	case IDGuid:
		e.buf = append(e.buf, 0x04|flags)
		e.WriteUint16(n.Namespace)
		e.WriteGuid(n.Guid)
	case IDByteString:
		e.buf = append(e.buf, 0x05|flags)
		e.WriteUint16(n.Namespace)
		e.WriteByteString([]byte(n.Str))
	}
}

func (e *Encoder) WriteNodeId(n NodeId) { e.writeNodeIdMask(n, 0) }

func (e *Encoder) WriteExpandedNodeId(n ExpandedNodeId) {
	var flags byte
	if n.NamespaceURI != "" {
		flags |= 0x80
	}
	if n.ServerIndex != 0 {
		flags |= 0x40
	}
	e.writeNodeIdMask(n.NodeId, flags)
	if n.NamespaceURI != "" {
		e.WriteString(n.NamespaceURI)
	}
	if n.ServerIndex != 0 {
		e.WriteUint32(n.ServerIndex)
	}
}

func (e *Encoder) WriteQualifiedName(q QualifiedName) {
	e.WriteUint16(q.NamespaceIndex)
	e.WriteString(q.Name)
}

func (e *Encoder) WriteLocalizedText(l LocalizedText) {
	var mask byte
	if l.Locale != "" {
		mask |= 1
	}
	if l.Text != "" {
		mask |= 2
	}
	e.buf = append(e.buf, mask)
	if l.Locale != "" {
		e.WriteString(l.Locale)
	}
	if l.Text != "" {
		e.WriteString(l.Text)
	}
}

// WriteStruct writes a structure body (not wrapped in an ExtensionObject).
func (e *Encoder) WriteStruct(s Structure) { s.Encode(e) }

func (e *Encoder) WriteExtensionObject(x ExtensionObject) {
	switch b := x.Value.(type) {
	case nil:
		e.WriteNodeId(x.TypeID.NodeId)
		e.buf = append(e.buf, 0)
	case Structure:
		e.WriteNodeId(b.BinaryEncodingID())
		e.buf = append(e.buf, 1)
		lenPos := len(e.buf)
		e.WriteInt32(0)
		b.Encode(e)
		binary.LittleEndian.PutUint32(e.buf[lenPos:], uint32(len(e.buf)-lenPos-4))
	case []byte:
		e.WriteNodeId(x.TypeID.NodeId)
		e.buf = append(e.buf, 1)
		e.WriteByteString(b)
	case XmlElement:
		e.WriteNodeId(x.TypeID.NodeId)
		e.buf = append(e.buf, 2)
		e.WriteXmlElement(b)
	default:
		e.WriteNodeId(NodeId{})
		e.buf = append(e.buf, 0)
	}
}

func (e *Encoder) WriteDataValue(v DataValue) {
	var mask byte
	if !v.Value.IsNull() {
		mask |= 0x01
	}
	if v.Status != 0 {
		mask |= 0x02
	}
	if !v.SourceTimestamp.IsZero() {
		mask |= 0x04
	}
	if !v.ServerTimestamp.IsZero() {
		mask |= 0x08
	}
	if v.SourcePicoseconds != 0 {
		mask |= 0x10
	}
	if v.ServerPicoseconds != 0 {
		mask |= 0x20
	}
	e.buf = append(e.buf, mask)
	if mask&0x01 != 0 {
		e.WriteVariant(v.Value)
	}
	if mask&0x02 != 0 {
		e.WriteStatusCode(v.Status)
	}
	if mask&0x04 != 0 {
		e.WriteDateTime(v.SourceTimestamp)
	}
	if mask&0x10 != 0 {
		e.WriteUint16(v.SourcePicoseconds)
	}
	if mask&0x08 != 0 {
		e.WriteDateTime(v.ServerTimestamp)
	}
	if mask&0x20 != 0 {
		e.WriteUint16(v.ServerPicoseconds)
	}
}

func (e *Encoder) WriteDiagnosticInfo(d *DiagnosticInfo) {
	if d == nil {
		e.buf = append(e.buf, 0)
		return
	}
	var mask byte
	if d.SymbolicID != nil {
		mask |= 0x01
	}
	if d.NamespaceURI != nil {
		mask |= 0x02
	}
	if d.LocalizedText != nil {
		mask |= 0x04
	}
	if d.Locale != nil {
		mask |= 0x08
	}
	if d.AdditionalInfo != nil {
		mask |= 0x10
	}
	if d.InnerStatusCode != nil {
		mask |= 0x20
	}
	if d.InnerDiagnosticInfo != nil {
		mask |= 0x40
	}
	e.buf = append(e.buf, mask)
	if d.SymbolicID != nil {
		e.WriteInt32(*d.SymbolicID)
	}
	if d.NamespaceURI != nil {
		e.WriteInt32(*d.NamespaceURI)
	}
	if d.Locale != nil {
		e.WriteInt32(*d.Locale)
	}
	if d.LocalizedText != nil {
		e.WriteInt32(*d.LocalizedText)
	}
	if d.AdditionalInfo != nil {
		e.WriteString(*d.AdditionalInfo)
	}
	if d.InnerStatusCode != nil {
		e.WriteStatusCode(*d.InnerStatusCode)
	}
	if d.InnerDiagnosticInfo != nil {
		e.WriteDiagnosticInfo(d.InnerDiagnosticInfo)
	}
}

func (e *Encoder) WriteVariant(v Variant) {
	if v.typ == TypeNull {
		e.buf = append(e.buf, 0)
		return
	}
	mask := byte(v.typ)
	if v.isArray {
		mask |= 0x80
		if len(v.dims) > 1 {
			mask |= 0x40
		}
	}
	e.buf = append(e.buf, mask)
	if !v.isArray {
		e.writeScalar(v.typ, v.value)
		return
	}
	e.writeArray(v.typ, v.value)
	if len(v.dims) > 1 {
		e.WriteInt32(int32(len(v.dims)))
		for _, d := range v.dims {
			e.WriteInt32(d)
		}
	}
}

func (e *Encoder) writeScalar(t TypeID, v any) {
	switch t {
	case TypeBoolean:
		e.WriteBool(v.(bool))
	case TypeSByte:
		e.WriteInt8(v.(int8))
	case TypeByte:
		e.WriteUint8(v.(byte))
	case TypeInt16:
		e.WriteInt16(v.(int16))
	case TypeUInt16:
		e.WriteUint16(v.(uint16))
	case TypeInt32:
		e.WriteInt32(v.(int32))
	case TypeUInt32:
		e.WriteUint32(v.(uint32))
	case TypeInt64:
		e.WriteInt64(v.(int64))
	case TypeUInt64:
		e.WriteUint64(v.(uint64))
	case TypeFloat:
		e.WriteFloat32(v.(float32))
	case TypeDouble:
		e.WriteFloat64(v.(float64))
	case TypeString:
		e.WriteString(v.(string))
	case TypeDateTime:
		e.WriteDateTime(v.(time.Time))
	case TypeGuid:
		e.WriteGuid(v.(Guid))
	case TypeByteString:
		e.WriteByteString(v.([]byte))
	case TypeXmlElement:
		e.WriteXmlElement(v.(XmlElement))
	case TypeNodeId:
		e.WriteNodeId(v.(NodeId))
	case TypeExpandedNodeId:
		e.WriteExpandedNodeId(v.(ExpandedNodeId))
	case TypeStatusCode:
		e.WriteStatusCode(v.(StatusCode))
	case TypeQualifiedName:
		e.WriteQualifiedName(v.(QualifiedName))
	case TypeLocalizedText:
		e.WriteLocalizedText(v.(LocalizedText))
	case TypeExtensionObject:
		e.WriteExtensionObject(v.(ExtensionObject))
	case TypeDataValue:
		e.WriteDataValue(v.(DataValue))
	case TypeVariant:
		e.WriteVariant(v.(Variant))
	case TypeDiagnosticInfo:
		e.WriteDiagnosticInfo(v.(*DiagnosticInfo))
	}
}

func writeSlice[T any](e *Encoder, a []T, f func(T)) {
	e.WriteInt32(int32(len(a)))
	for _, x := range a {
		f(x)
	}
}

func (e *Encoder) writeArray(t TypeID, v any) {
	switch t {
	case TypeBoolean:
		writeSlice(e, v.([]bool), e.WriteBool)
	case TypeSByte:
		writeSlice(e, v.([]int8), e.WriteInt8)
	case TypeByte:
		writeSlice(e, v.([]byte), e.WriteUint8)
	case TypeInt16:
		writeSlice(e, v.([]int16), e.WriteInt16)
	case TypeUInt16:
		writeSlice(e, v.([]uint16), e.WriteUint16)
	case TypeInt32:
		writeSlice(e, v.([]int32), e.WriteInt32)
	case TypeUInt32:
		writeSlice(e, v.([]uint32), e.WriteUint32)
	case TypeInt64:
		writeSlice(e, v.([]int64), e.WriteInt64)
	case TypeUInt64:
		writeSlice(e, v.([]uint64), e.WriteUint64)
	case TypeFloat:
		writeSlice(e, v.([]float32), e.WriteFloat32)
	case TypeDouble:
		writeSlice(e, v.([]float64), e.WriteFloat64)
	case TypeString:
		writeSlice(e, v.([]string), e.WriteString)
	case TypeDateTime:
		writeSlice(e, v.([]time.Time), e.WriteDateTime)
	case TypeGuid:
		writeSlice(e, v.([]Guid), e.WriteGuid)
	case TypeByteString:
		writeSlice(e, v.([][]byte), e.WriteByteString)
	case TypeXmlElement:
		writeSlice(e, v.([]XmlElement), e.WriteXmlElement)
	case TypeNodeId:
		writeSlice(e, v.([]NodeId), e.WriteNodeId)
	case TypeExpandedNodeId:
		writeSlice(e, v.([]ExpandedNodeId), e.WriteExpandedNodeId)
	case TypeStatusCode:
		writeSlice(e, v.([]StatusCode), e.WriteStatusCode)
	case TypeQualifiedName:
		writeSlice(e, v.([]QualifiedName), e.WriteQualifiedName)
	case TypeLocalizedText:
		writeSlice(e, v.([]LocalizedText), e.WriteLocalizedText)
	case TypeExtensionObject:
		writeSlice(e, v.([]ExtensionObject), e.WriteExtensionObject)
	case TypeDataValue:
		writeSlice(e, v.([]DataValue), e.WriteDataValue)
	case TypeVariant:
		writeSlice(e, v.([]Variant), e.WriteVariant)
	case TypeDiagnosticInfo:
		writeSlice(e, v.([]*DiagnosticInfo), e.WriteDiagnosticInfo)
	}
}

// Decoder reads values in UA Binary encoding. Errors are sticky: after the
// first error all reads return zero values and Err returns the error.
type Decoder struct {
	buf   []byte
	pos   int
	err   error
	depth int
}

// NewDecoder returns a decoder reading from b.
func NewDecoder(b []byte) *Decoder { return &Decoder{buf: b} }

// Err returns the first error encountered.
func (d *Decoder) Err() error { return d.err }

// Remaining returns the number of unread bytes.
func (d *Decoder) Remaining() int { return len(d.buf) - d.pos }

// Pos returns the read offset.
func (d *Decoder) Pos() int { return d.pos }

// Fail records an error.
func (d *Decoder) Fail(err error) {
	if d.err == nil {
		d.err = err
	}
}

func (d *Decoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || d.pos+n > len(d.buf) {
		d.err = ErrDecoding
		d.pos = len(d.buf)
		return nil
	}
	b := d.buf[d.pos : d.pos+n]
	d.pos += n
	return b
}

// ReadRaw reads n raw bytes.
func (d *Decoder) ReadRaw(n int) []byte { return d.take(n) }

func (d *Decoder) ReadBool() bool { b := d.take(1); return b != nil && b[0] != 0 }
func (d *Decoder) ReadInt8() int8 { return int8(d.ReadUint8()) }
func (d *Decoder) ReadUint8() byte {
	if b := d.take(1); b != nil {
		return b[0]
	}
	return 0
}
func (d *Decoder) ReadInt16() int16 { return int16(d.ReadUint16()) }
func (d *Decoder) ReadUint16() uint16 {
	if b := d.take(2); b != nil {
		return binary.LittleEndian.Uint16(b)
	}
	return 0
}
func (d *Decoder) ReadInt32() int32 { return int32(d.ReadUint32()) }
func (d *Decoder) ReadUint32() uint32 {
	if b := d.take(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}
func (d *Decoder) ReadInt64() int64 { return int64(d.ReadUint64()) }
func (d *Decoder) ReadUint64() uint64 {
	if b := d.take(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}
func (d *Decoder) ReadFloat32() float32 { return math.Float32frombits(d.ReadUint32()) }
func (d *Decoder) ReadFloat64() float64 { return math.Float64frombits(d.ReadUint64()) }

func (d *Decoder) ReadString() string {
	n := d.ReadInt32()
	if n <= 0 {
		return ""
	}
	if n > MaxStringLength {
		d.Fail(ErrDecoding)
		return ""
	}
	return string(d.take(int(n)))
}

func (d *Decoder) ReadByteString() []byte {
	n := d.ReadInt32()
	if n < 0 || d.err != nil {
		return nil
	}
	if n > MaxStringLength {
		d.Fail(ErrDecoding)
		return nil
	}
	b := d.take(int(n))
	if b == nil {
		return nil
	}
	return append([]byte{}, b...)
}

func (d *Decoder) ReadXmlElement() XmlElement { return XmlElement(d.ReadString()) }
func (d *Decoder) ReadDateTime() time.Time    { return TicksToTime(d.ReadInt64()) }
func (d *Decoder) ReadGuid() Guid {
	var g Guid
	copy(g[:], d.take(16))
	return g
}
func (d *Decoder) ReadStatusCode() StatusCode { return StatusCode(d.ReadUint32()) }

// ReadArrayLength reads an array length prefix. It returns -1 for null arrays.
func (d *Decoder) ReadArrayLength() int {
	n := d.ReadInt32()
	if d.err != nil || n < 0 {
		return -1
	}
	if n > MaxArrayLength || int(n) > d.Remaining() {
		d.Fail(ErrDecoding)
		return -1
	}
	return int(n)
}

func (d *Decoder) readNodeIdBody(mask byte) NodeId {
	var n NodeId
	switch mask & 0x0F {
	case 0x00:
		n.Numeric = uint32(d.ReadUint8())
	case 0x01:
		n.Namespace = uint16(d.ReadUint8())
		n.Numeric = uint32(d.ReadUint16())
	case 0x02:
		n.Namespace = d.ReadUint16()
		n.Numeric = d.ReadUint32()
	case 0x03:
		n.Namespace = d.ReadUint16()
		n.Type = IDString
		n.Str = d.ReadString()
	case 0x04:
		n.Namespace = d.ReadUint16()
		n.Type = IDGuid
		n.Guid = d.ReadGuid()
	case 0x05:
		n.Namespace = d.ReadUint16()
		n.Type = IDByteString
		n.Str = string(d.ReadByteString())
	default:
		d.Fail(ErrDecoding)
	}
	return n
}

func (d *Decoder) ReadNodeId() NodeId {
	mask := d.ReadUint8()
	if mask&0xF0 != 0 {
		d.Fail(ErrDecoding)
		return NodeId{}
	}
	return d.readNodeIdBody(mask)
}

func (d *Decoder) ReadExpandedNodeId() ExpandedNodeId {
	mask := d.ReadUint8()
	var e ExpandedNodeId
	e.NodeId = d.readNodeIdBody(mask)
	if mask&0x80 != 0 {
		e.NamespaceURI = d.ReadString()
	}
	if mask&0x40 != 0 {
		e.ServerIndex = d.ReadUint32()
	}
	return e
}

func (d *Decoder) ReadQualifiedName() QualifiedName {
	ns := d.ReadUint16()
	return QualifiedName{NamespaceIndex: ns, Name: d.ReadString()}
}

func (d *Decoder) ReadLocalizedText() LocalizedText {
	var l LocalizedText
	mask := d.ReadUint8()
	if mask&1 != 0 {
		l.Locale = d.ReadString()
	}
	if mask&2 != 0 {
		l.Text = d.ReadString()
	}
	return l
}

// ReadStruct decodes a structure body into s.
func (d *Decoder) ReadStruct(s Structure) {
	if !d.enter() {
		return
	}
	s.Decode(d)
	d.depth--
}

func (d *Decoder) enter() bool {
	d.depth++
	if d.depth > MaxNestingDepth {
		d.Fail(ErrDecoding)
		d.depth--
		return false
	}
	return true
}

func (d *Decoder) ReadExtensionObject() ExtensionObject {
	var x ExtensionObject
	x.TypeID = NewExpandedNodeId(d.ReadNodeId())
	enc := d.ReadUint8()
	switch enc {
	case 0:
	case 1:
		n := d.ReadInt32()
		if n < 0 {
			return x
		}
		body := d.take(int(n))
		if d.err != nil {
			return x
		}
		if s := NewStructureByEncodingID(x.TypeID.NodeId); s != nil {
			sub := &Decoder{buf: body, depth: d.depth}
			sub.ReadStruct(s)
			if sub.err != nil {
				d.Fail(sub.err)
				return x
			}
			x.Value = s
		} else {
			x.Value = append([]byte{}, body...)
		}
	case 2:
		x.Value = d.ReadXmlElement()
	default:
		d.Fail(ErrDecoding)
	}
	return x
}

func (d *Decoder) ReadDataValue() DataValue {
	var v DataValue
	mask := d.ReadUint8()
	if mask&0x01 != 0 {
		v.Value = d.ReadVariant()
	}
	if mask&0x02 != 0 {
		v.Status = d.ReadStatusCode()
	}
	if mask&0x04 != 0 {
		v.SourceTimestamp = d.ReadDateTime()
	}
	if mask&0x10 != 0 {
		v.SourcePicoseconds = d.ReadUint16()
	}
	if mask&0x08 != 0 {
		v.ServerTimestamp = d.ReadDateTime()
	}
	if mask&0x20 != 0 {
		v.ServerPicoseconds = d.ReadUint16()
	}
	return v
}

func (d *Decoder) ReadDiagnosticInfo() *DiagnosticInfo {
	mask := d.ReadUint8()
	if mask == 0 || d.err != nil {
		return nil
	}
	if !d.enter() {
		return nil
	}
	defer func() { d.depth-- }()
	di := &DiagnosticInfo{}
	i32 := func() *int32 { v := d.ReadInt32(); return &v }
	if mask&0x01 != 0 {
		di.SymbolicID = i32()
	}
	if mask&0x02 != 0 {
		di.NamespaceURI = i32()
	}
	if mask&0x08 != 0 {
		di.Locale = i32()
	}
	if mask&0x04 != 0 {
		di.LocalizedText = i32()
	}
	if mask&0x10 != 0 {
		s := d.ReadString()
		di.AdditionalInfo = &s
	}
	if mask&0x20 != 0 {
		s := d.ReadStatusCode()
		di.InnerStatusCode = &s
	}
	if mask&0x40 != 0 {
		di.InnerDiagnosticInfo = d.ReadDiagnosticInfo()
	}
	return di
}

func (d *Decoder) ReadVariant() Variant {
	mask := d.ReadUint8()
	if d.err != nil || mask == 0 {
		return Variant{}
	}
	if !d.enter() {
		return Variant{}
	}
	defer func() { d.depth-- }()
	t := TypeID(mask & 0x3F)
	if t > TypeDiagnosticInfo {
		d.Fail(ErrDecoding)
		return Variant{}
	}
	if mask&0x80 == 0 {
		return Variant{typ: t, value: d.readScalar(t)}
	}
	n := d.ReadArrayLength()
	v := Variant{typ: t, isArray: true, value: d.readArray(t, n)}
	if mask&0x40 != 0 {
		nd := d.ReadArrayLength()
		if nd > 0 {
			v.dims = make([]int32, nd)
			total := int64(1)
			for i := range v.dims {
				v.dims[i] = d.ReadInt32()
				total *= int64(v.dims[i])
			}
			if d.err == nil && (total != int64(max(n, 0)) || nd < 2) {
				if nd == 1 {
					v.dims = nil
				} else {
					d.Fail(ErrDecoding)
				}
			}
		}
	}
	return v
}

func (d *Decoder) readScalar(t TypeID) any {
	switch t {
	case TypeBoolean:
		return d.ReadBool()
	case TypeSByte:
		return d.ReadInt8()
	case TypeByte:
		return d.ReadUint8()
	case TypeInt16:
		return d.ReadInt16()
	case TypeUInt16:
		return d.ReadUint16()
	case TypeInt32:
		return d.ReadInt32()
	case TypeUInt32:
		return d.ReadUint32()
	case TypeInt64:
		return d.ReadInt64()
	case TypeUInt64:
		return d.ReadUint64()
	case TypeFloat:
		return d.ReadFloat32()
	case TypeDouble:
		return d.ReadFloat64()
	case TypeString:
		return d.ReadString()
	case TypeDateTime:
		return d.ReadDateTime()
	case TypeGuid:
		return d.ReadGuid()
	case TypeByteString:
		return d.ReadByteString()
	case TypeXmlElement:
		return d.ReadXmlElement()
	case TypeNodeId:
		return d.ReadNodeId()
	case TypeExpandedNodeId:
		return d.ReadExpandedNodeId()
	case TypeStatusCode:
		return d.ReadStatusCode()
	case TypeQualifiedName:
		return d.ReadQualifiedName()
	case TypeLocalizedText:
		return d.ReadLocalizedText()
	case TypeExtensionObject:
		return d.ReadExtensionObject()
	case TypeDataValue:
		return d.ReadDataValue()
	case TypeVariant:
		// A Variant may not directly contain a scalar Variant.
		d.Fail(ErrDecoding)
		return nil
	case TypeDiagnosticInfo:
		return d.ReadDiagnosticInfo()
	}
	return nil
}

func readSlice[T any](n int, f func() T) []T {
	if n < 0 {
		return nil
	}
	a := make([]T, n)
	for i := range a {
		a[i] = f()
	}
	return a
}

func (d *Decoder) readArray(t TypeID, n int) any {
	switch t {
	case TypeBoolean:
		return readSlice(n, d.ReadBool)
	case TypeSByte:
		return readSlice(n, d.ReadInt8)
	case TypeByte:
		return readSlice(n, d.ReadUint8)
	case TypeInt16:
		return readSlice(n, d.ReadInt16)
	case TypeUInt16:
		return readSlice(n, d.ReadUint16)
	case TypeInt32:
		return readSlice(n, d.ReadInt32)
	case TypeUInt32:
		return readSlice(n, d.ReadUint32)
	case TypeInt64:
		return readSlice(n, d.ReadInt64)
	case TypeUInt64:
		return readSlice(n, d.ReadUint64)
	case TypeFloat:
		return readSlice(n, d.ReadFloat32)
	case TypeDouble:
		return readSlice(n, d.ReadFloat64)
	case TypeString:
		return readSlice(n, d.ReadString)
	case TypeDateTime:
		return readSlice(n, d.ReadDateTime)
	case TypeGuid:
		return readSlice(n, d.ReadGuid)
	case TypeByteString:
		return readSlice(n, d.ReadByteString)
	case TypeXmlElement:
		return readSlice(n, d.ReadXmlElement)
	case TypeNodeId:
		return readSlice(n, d.ReadNodeId)
	case TypeExpandedNodeId:
		return readSlice(n, d.ReadExpandedNodeId)
	case TypeStatusCode:
		return readSlice(n, d.ReadStatusCode)
	case TypeQualifiedName:
		return readSlice(n, d.ReadQualifiedName)
	case TypeLocalizedText:
		return readSlice(n, d.ReadLocalizedText)
	case TypeExtensionObject:
		return readSlice(n, d.ReadExtensionObject)
	case TypeDataValue:
		return readSlice(n, d.ReadDataValue)
	case TypeVariant:
		return readSlice(n, d.ReadVariant)
	case TypeDiagnosticInfo:
		return readSlice(n, d.ReadDiagnosticInfo)
	}
	return nil
}

// Encode encodes a structure to bytes.
func Encode(s Structure) []byte {
	e := NewEncoder(256)
	s.Encode(e)
	return e.Bytes()
}

// Decode decodes a structure from bytes.
func Decode(b []byte, s Structure) error {
	d := NewDecoder(b)
	d.ReadStruct(s)
	return d.Err()
}
