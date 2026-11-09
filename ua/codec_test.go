package ua

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestNodeIdEncoding(t *testing.T) {
	cases := []struct {
		n    NodeId
		want []byte
	}{
		{NewNumericNodeId(0, 72), []byte{0x00, 0x48}},
		{NewNumericNodeId(5, 1025), []byte{0x01, 0x05, 0x01, 0x04}},
		{NewStringNodeId(1, "Hot水"), []byte{0x03, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 'H', 'o', 't', 0xE6, 0xB0, 0xB4}},
	}
	for _, c := range cases {
		e := NewEncoder(16)
		e.WriteNodeId(c.n)
		if !bytes.Equal(e.Bytes(), c.want) {
			t.Errorf("%s: got % x want % x", c.n, e.Bytes(), c.want)
		}
		if got := NewDecoder(c.want).ReadNodeId(); got != c.n {
			t.Errorf("decode %s: got %s", c.n, got)
		}
	}
}

func TestParseNodeId(t *testing.T) {
	for _, s := range []string{"i=85", "ns=2;s=Demo.Static", "ns=1;g=72962B91-FA75-4AE6-8D28-B404DC7DAF63", "ns=3;b=AQID"} {
		n, err := ParseNodeId(s)
		if err != nil {
			t.Fatal(err)
		}
		if n.String() != s {
			t.Errorf("round trip %q -> %q", s, n.String())
		}
	}
}

func TestGuidWireOrder(t *testing.T) {
	g, err := ParseGuid("72962B91-FA75-4AE6-8D28-B404DC7DAF63")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x91, 0x2B, 0x96, 0x72, 0x75, 0xFA, 0xE6, 0x4A, 0x8D, 0x28, 0xB4, 0x04, 0xDC, 0x7D, 0xAF, 0x63}
	if !bytes.Equal(g[:], want) {
		t.Fatalf("got % x", g[:])
	}
}

func TestDateTime(t *testing.T) {
	tm := time.Date(2024, 5, 6, 7, 8, 9, 123456700, time.UTC)
	if got := TicksToTime(TimeToTicks(tm)); !got.Equal(tm) {
		t.Fatalf("got %v", got)
	}
	if TimeToTicks(time.Time{}) != 0 || !TicksToTime(0).IsZero() {
		t.Fatal("zero time must map to 0")
	}
}

func TestVariantRoundTrip(t *testing.T) {
	m, err := NewMatrixVariant([]int32{1, 2, 3, 4, 5, 6}, []int32{2, 3})
	if err != nil {
		t.Fatal(err)
	}
	values := []Variant{
		{}, NewVariant(true), NewVariant(int8(-3)), NewVariant(byte(7)), NewVariant(int16(-300)),
		NewVariant(uint16(300)), NewVariant(int32(-70000)), NewVariant(uint32(70000)), NewVariant(int64(-1 << 40)),
		NewVariant(uint64(1 << 40)), NewVariant(float32(1.5)), NewVariant(2.25), NewVariant("text"),
		NewVariant(time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)), NewVariant(NewGuid()), NewVariant([]byte{1, 2}),
		NewVariant(NewStringNodeId(2, "x")), NewVariant(ExpandedNodeId{NodeId: NewNumericNodeId(0, 1), NamespaceURI: "urn:x", ServerIndex: 2}),
		NewVariant(StatusBadTimeout), NewVariant(NewQualifiedName(1, "q")), NewVariant(LocalizedText{"en", "hi"}),
		NewVariant([]string{"a", "b"}), NewVariant([]float64{1, 2}), NewByteArrayVariant([]byte{9, 8}),
		NewVariant([]Variant{NewVariant(int32(1)), NewVariant("s")}), m,
		NewVariant(&Range{Low: 1, High: 2}), NewVariant(DataValue{Value: NewVariant(int32(1)), Status: StatusUncertain}),
	}
	for _, v := range values {
		e := NewEncoder(64)
		e.WriteVariant(v)
		d := NewDecoder(e.Bytes())
		got := d.ReadVariant()
		if d.Err() != nil || d.Remaining() != 0 {
			t.Fatalf("%v: decode error %v, remaining %d", v, d.Err(), d.Remaining())
		}
		if !reflect.DeepEqual(got, v) {
			t.Errorf("round trip mismatch:\n got  %#v\n want %#v", got, v)
		}
	}
}

func TestStructureRoundTrip(t *testing.T) {
	req := &ReadRequest{
		RequestHeader:      RequestHeader{AuthenticationToken: NewNumericNodeId(1, 5), RequestHandle: 9, Timestamp: time.Unix(1700000000, 0).UTC()},
		MaxAge:             100,
		TimestampsToReturn: TimestampsToReturnBoth,
		NodesToRead:        []ReadValueId{{NodeId: NewNumericNodeId(0, 2258), AttributeId: 13}},
	}
	b := Encode(req)
	var got ReadRequest
	if err := Decode(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&got, req) {
		t.Fatalf("mismatch:\n%#v\n%#v", got, req)
	}
	eo := NewExtensionObject(req)
	e := NewEncoder(64)
	e.WriteExtensionObject(eo)
	d := NewDecoder(e.Bytes())
	x := d.ReadExtensionObject()
	if _, ok := x.Value.(*ReadRequest); !ok || d.Err() != nil {
		t.Fatalf("extension object decode: %T %v", x.Value, d.Err())
	}
}

func TestDecoderLimits(t *testing.T) {
	// An array length larger than the remaining bytes must fail without allocating.
	d := NewDecoder([]byte{0x86, 0xFF, 0xFF, 0xFF, 0x7F})
	d.ReadVariant()
	if d.Err() == nil {
		t.Fatal("expected error")
	}
	// Deeply nested variants must be rejected.
	var b []byte
	for i := 0; i < 200; i++ {
		b = append(b, 0x98, 1, 0, 0, 0)
	}
	d = NewDecoder(b)
	d.ReadVariant()
	if d.Err() == nil {
		t.Fatal("expected nesting error")
	}
}
