// Codec micro benchmarks: the same messages encoded and decoded with the
// uaserver and gopcua UA Binary codecs.
//
//	cd bench && go test -bench . -benchmem
package bench

import (
	"bytes"
	"testing"
	"time"

	gua "github.com/gopcua/opcua/ua"

	"github.com/bamchoh/uaserver/ua"
)

const nValues = 1000

var ts = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// A ReadResponse with 1000 Int32 values and source/server timestamps.

func uaReadResponse() *ua.ReadResponse {
	r := &ua.ReadResponse{ResponseHeader: ua.ResponseHeader{Timestamp: ts, RequestHandle: 1}}
	r.Results = make([]ua.DataValue, nValues)
	for i := range r.Results {
		r.Results[i] = ua.DataValue{Value: ua.NewVariant(int32(i)), SourceTimestamp: ts, ServerTimestamp: ts}
	}
	return r
}

func gReadResponse() *gua.ReadResponse {
	r := &gua.ReadResponse{ResponseHeader: &gua.ResponseHeader{
		Timestamp: ts, RequestHandle: 1,
		ServiceDiagnostics: &gua.DiagnosticInfo{}, AdditionalHeader: gua.NewExtensionObject(nil),
	}}
	r.Results = make([]*gua.DataValue, nValues)
	for i := range r.Results {
		r.Results[i] = &gua.DataValue{
			EncodingMask:    gua.DataValueValue | gua.DataValueSourceTimestamp | gua.DataValueServerTimestamp,
			Value:           gua.MustVariant(int32(i)),
			SourceTimestamp: ts, ServerTimestamp: ts,
		}
	}
	return r
}

// A ReadRequest for 1000 string node ids.

func uaReadRequest() *ua.ReadRequest {
	r := &ua.ReadRequest{RequestHeader: ua.RequestHeader{Timestamp: ts, RequestHandle: 1}, TimestampsToReturn: ua.TimestampsToReturnBoth}
	r.NodesToRead = make([]ua.ReadValueId, nValues)
	for i := range r.NodesToRead {
		r.NodesToRead[i] = ua.ReadValueId{NodeId: ua.NewStringNodeId(2, "v"+itoa(i)), AttributeId: 13}
	}
	return r
}

func gReadRequest() *gua.ReadRequest {
	r := &gua.ReadRequest{
		RequestHeader: &gua.RequestHeader{Timestamp: ts, RequestHandle: 1,
			AuthenticationToken: gua.NewTwoByteNodeID(0), AdditionalHeader: gua.NewExtensionObject(nil)},
		TimestampsToReturn: gua.TimestampsToReturnBoth,
	}
	r.NodesToRead = make([]*gua.ReadValueID, nValues)
	for i := range r.NodesToRead {
		r.NodesToRead[i] = &gua.ReadValueID{NodeID: gua.NewStringNodeID(2, "v"+itoa(i)),
			AttributeID: gua.AttributeIDValue, DataEncoding: &gua.QualifiedName{}}
	}
	return r
}

func itoa(i int) string {
	var b [8]byte
	p := len(b)
	for {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
		if i == 0 {
			return string(b[p:])
		}
	}
}

// The two codecs must produce the same bytes, otherwise the comparison is meaningless.
func TestSameEncoding(t *testing.T) {
	g, err := gua.Encode(gReadResponse())
	if err != nil {
		t.Fatal(err)
	}
	if u := ua.Encode(uaReadResponse()); !bytes.Equal(u, g) {
		t.Fatalf("ReadResponse encodings differ: %d vs %d bytes", len(u), len(g))
	}
	g, err = gua.Encode(gReadRequest())
	if err != nil {
		t.Fatal(err)
	}
	if u := ua.Encode(uaReadRequest()); !bytes.Equal(u, g) {
		t.Fatalf("ReadRequest encodings differ: %d vs %d bytes", len(u), len(g))
	}
}

func BenchmarkEncodeReadResponse(b *testing.B) {
	b.Run("uaserver", func(b *testing.B) {
		m := uaReadResponse()
		b.ReportAllocs()
		for b.Loop() {
			_ = ua.Encode(m)
		}
	})
	b.Run("gopcua", func(b *testing.B) {
		m := gReadResponse()
		b.ReportAllocs()
		for b.Loop() {
			if _, err := gua.Encode(m); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkDecodeReadResponse(b *testing.B) {
	data := ua.Encode(uaReadResponse())
	b.Run("uaserver", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var m ua.ReadResponse
			if err := ua.Decode(data, &m); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("gopcua", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var m gua.ReadResponse
			if _, err := gua.Decode(data, &m); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkEncodeReadRequest(b *testing.B) {
	b.Run("uaserver", func(b *testing.B) {
		m := uaReadRequest()
		b.ReportAllocs()
		for b.Loop() {
			_ = ua.Encode(m)
		}
	})
	b.Run("gopcua", func(b *testing.B) {
		m := gReadRequest()
		b.ReportAllocs()
		for b.Loop() {
			if _, err := gua.Encode(m); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkDecodeReadRequest(b *testing.B) {
	data := ua.Encode(uaReadRequest())
	b.Run("uaserver", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var m ua.ReadRequest
			if err := ua.Decode(data, &m); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("gopcua", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var m gua.ReadRequest
			if _, err := gua.Decode(data, &m); err != nil {
				b.Fatal(err)
			}
		}
	})
}
