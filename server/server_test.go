package server

import (
	"io"
	"log"
	"testing"

	"github.com/bamchoh/uastack/ua"
	"github.com/bamchoh/uastack/ua/id"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{PKIDir: t.TempDir(), Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAddressSpaceLoaded(t *testing.T) {
	s := newTestServer(t)
	for _, i := range []uint32{id.RootFolder, id.ObjectsFolder, id.Server, id.Server_ServerStatus, id.HasComponent, id.FolderType} {
		if s.as.Node(nid(i)) == nil {
			t.Fatalf("node i=%d missing", i)
		}
	}
	if !s.as.IsSubtype(RefHasComponent, RefHierarchical) {
		t.Fatal("HasComponent must be a hierarchical reference")
	}
	if !s.as.IsSubtype(nid(id.UtcTime), nid(id.DateTime)) {
		t.Fatal("UtcTime must derive from DateTime")
	}
	// A structured value from the NodeSet (EnumValues / Argument).
	v, err := s.as.Value(nid(id.ServerType_GetMonitoredItems_InputArguments))
	if err != nil {
		t.Fatal(err)
	}
	eos, ok := v.Value.Value().([]ua.ExtensionObject)
	if !ok || len(eos) != 1 {
		t.Fatalf("unexpected InputArguments value %v", v.Value)
	}
	if a, ok := eos[0].Value.(*ua.Argument); !ok || a.Name != "SubscriptionId" {
		t.Fatalf("unexpected argument %#v", eos[0].Value)
	}
}

func TestReadWriteBrowse(t *testing.T) {
	s := newTestServer(t)
	ns := s.as.RegisterNamespace("urn:test")
	vid := ua.NewStringNodeId(ns, "v")
	if _, err := s.as.AddVariable(ObjectsFolder, vid, ua.NewQualifiedName(ns, "v"), ua.NewVariant(int32(1)),
		VariableOptions{AccessLevel: AccessCurrentRead | AccessCurrentWrite}); err != nil {
		t.Fatal(err)
	}
	sess := &Session{srv: s, browseCPs: map[string]*browseCP{}}

	rr := s.read(sess, &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnBoth, NodesToRead: []ua.ReadValueId{
		{NodeId: vid, AttributeId: AttrValue},
		{NodeId: vid, AttributeId: AttrDataType},
		{NodeId: vid, AttributeId: AttrIsAbstract},
		{NodeId: nid(id.Server_NamespaceArray), AttributeId: AttrValue},
		{NodeId: nid(id.BuildInfo), AttributeId: AttrDataTypeDefinition},
	}}).(*ua.ReadResponse)
	if r := rr.Results; r[0].Value.Value() != int32(1) || r[1].Value.Value() != nid(id.Int32) ||
		r[2].Status != ua.StatusBadAttributeIdInvalid {
		t.Fatalf("unexpected read results %+v", r)
	}
	if nsa := rr.Results[3].Value.Value().([]string); len(nsa) != 3 || nsa[2] != "urn:test" {
		t.Fatalf("namespace array %v", nsa)
	}
	eo := rr.Results[4].Value.Value().(ua.ExtensionObject)
	if sd, ok := eo.Value.(*ua.StructureDefinition); !ok || len(sd.Fields) != 6 {
		t.Fatalf("BuildInfo definition %#v", eo.Value)
	}

	wr := s.write(sess, &ua.WriteRequest{NodesToWrite: []ua.WriteValue{
		{NodeId: vid, AttributeId: AttrValue, Value: ua.NewDataValue(ua.NewVariant(int32(7)))},
		{NodeId: vid, AttributeId: AttrValue, Value: ua.NewDataValue(ua.NewVariant(7.0))},
		{NodeId: vid, AttributeId: AttrDisplayName, Value: ua.NewDataValue(ua.NewVariant(ua.NewLocalizedText("x")))},
	}}).(*ua.WriteResponse)
	if r := wr.Results; r[0] != 0 || r[1] != ua.StatusBadTypeMismatch || r[2] != ua.StatusBadNotWritable {
		t.Fatalf("unexpected write results %v", r)
	}

	br := s.browse(sess, &ua.BrowseRequest{RequestedMaxReferencesPerNode: 2, NodesToBrowse: []ua.BrowseDescription{{
		NodeId: ObjectsFolder, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeId: RefHierarchical,
		IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll),
	}}}).(*ua.BrowseResponse)
	first := br.Results[0]
	if len(first.References) != 2 || first.ContinuationPoint == nil {
		t.Fatalf("expected paged browse, got %+v", first)
	}
	bn := s.browseNext(sess, &ua.BrowseNextRequest{ContinuationPoints: [][]byte{first.ContinuationPoint}}).(*ua.BrowseNextResponse)
	if len(bn.Results[0].References) == 0 || bn.Results[0].StatusCode != 0 {
		t.Fatalf("browse next %+v", bn.Results[0])
	}

	tr := s.translatePath(ua.BrowsePath{StartingNode: RootFolder, RelativePath: ua.RelativePath{Elements: []ua.RelativePathElement{
		{ReferenceTypeId: RefHierarchical, IncludeSubtypes: true, TargetName: ua.NewQualifiedName(0, "Objects")},
		{ReferenceTypeId: RefHierarchical, IncludeSubtypes: true, TargetName: ua.NewQualifiedName(ns, "v")},
	}}})
	if tr.StatusCode != 0 || len(tr.Targets) != 1 || tr.Targets[0].TargetId.NodeId != vid {
		t.Fatalf("translate %+v", tr)
	}
}

func TestCallMethod(t *testing.T) {
	s := newTestServer(t)
	ns := s.as.RegisterNamespace("urn:test")
	obj := ua.NewStringNodeId(ns, "o")
	if _, err := s.as.AddObject(ObjectsFolder, obj, ua.NewQualifiedName(ns, "o"), ua.NodeId{}); err != nil {
		t.Fatal(err)
	}
	m := ua.NewStringNodeId(ns, "o.neg")
	i32 := nid(id.Int32)
	if _, err := s.as.AddMethod(obj, m, ua.NewQualifiedName(ns, "neg"), []Argument{{Name: "x", DataType: i32}}, []Argument{{Name: "y", DataType: i32}},
		func(_ ReadContext, _ ua.NodeId, in []ua.Variant) ([]ua.Variant, ua.StatusCode) {
			return []ua.Variant{ua.NewVariant(-in[0].Value().(int32))}, 0
		}); err != nil {
		t.Fatal(err)
	}
	r := s.callMethod(ReadContext{}, ua.CallMethodRequest{ObjectId: obj, MethodId: m, InputArguments: []ua.Variant{ua.NewVariant(int32(5))}})
	if r.StatusCode != 0 || r.OutputArguments[0].Value() != int32(-5) {
		t.Fatalf("call %+v", r)
	}
	r = s.callMethod(ReadContext{}, ua.CallMethodRequest{ObjectId: obj, MethodId: m, InputArguments: []ua.Variant{ua.NewVariant("x")}})
	if r.StatusCode != ua.StatusBadInvalidArgument {
		t.Fatalf("expected BadInvalidArgument, got %s", r.StatusCode)
	}
	r = s.callMethod(ReadContext{}, ua.CallMethodRequest{ObjectId: obj, MethodId: m})
	if r.StatusCode != ua.StatusBadArgumentsMissing {
		t.Fatalf("expected BadArgumentsMissing, got %s", r.StatusCode)
	}
}

func TestMatrixVariables(t *testing.T) {
	s := newTestServer(t)
	ns := s.as.RegisterNamespace("urn:test")
	mid := ua.NewStringNodeId(ns, "m")
	m, err := ua.NewMatrixVariant([]byte{0, 1, 2, 3, 4, 5}, []int32{2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.as.AddVariable(ObjectsFolder, mid, ua.NewQualifiedName(ns, "m"), m,
		VariableOptions{AccessLevel: AccessCurrentRead | AccessCurrentWrite}); err != nil {
		t.Fatal(err)
	}
	sess := &Session{srv: s, browseCPs: map[string]*browseCP{}}
	rr := s.read(sess, &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither, NodesToRead: []ua.ReadValueId{
		{NodeId: mid, AttributeId: AttrValue},
		{NodeId: mid, AttributeId: AttrValueRank},
		{NodeId: mid, AttributeId: AttrArrayDimensions},
		{NodeId: mid, AttributeId: AttrDataType},
	}}).(*ua.ReadResponse)
	r := rr.Results
	if v := r[0].Value; v.Type() != ua.TypeByte || !v.IsArray() || len(v.Dimensions()) != 2 {
		t.Fatalf("matrix value %#v", v)
	}
	if r[1].Value.Value() != int32(2) || len(r[2].Value.Value().([]uint32)) != 2 || r[3].Value.Value() != nid(id.Byte) {
		t.Fatalf("matrix attributes %+v", r[1:])
	}

	write := func(v ua.Variant) ua.StatusCode {
		wr := s.write(sess, &ua.WriteRequest{NodesToWrite: []ua.WriteValue{
			{NodeId: mid, AttributeId: AttrValue, Value: ua.NewDataValue(v)}}}).(*ua.WriteResponse)
		return wr.Results[0]
	}
	smaller, _ := ua.NewMatrixVariant([]byte{9, 9}, []int32{1, 2})
	bigger, _ := ua.NewMatrixVariant(make([]byte, 8), []int32{2, 4})
	cube, _ := ua.NewMatrixVariant(make([]byte, 8), []int32{2, 2, 2})
	if st := write(smaller); st != 0 {
		t.Fatalf("smaller matrix: %s", st)
	}
	for name, v := range map[string]ua.Variant{
		"larger than ArrayDimensions": bigger,
		"wrong rank":                  cube,
		"one dimensional":             ua.NewByteArrayVariant([]byte{1, 2}),
		"scalar":                      ua.NewVariant(byte(1)),
	} {
		if st := write(v); st != ua.StatusBadTypeMismatch {
			t.Errorf("%s: got %s, want BadTypeMismatch", name, st)
		}
	}
}
