package server

import (
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/bamchoh/uastack/ua"
	"github.com/bamchoh/uastack/ua/id"
)

// Attribute ids (Part 6, A.1).
const (
	AttrNodeId                  = 1
	AttrNodeClass               = 2
	AttrBrowseName              = 3
	AttrDisplayName             = 4
	AttrDescription             = 5
	AttrWriteMask               = 6
	AttrUserWriteMask           = 7
	AttrIsAbstract              = 8
	AttrSymmetric               = 9
	AttrInverseName             = 10
	AttrContainsNoLoops         = 11
	AttrEventNotifier           = 12
	AttrValue                   = 13
	AttrDataType                = 14
	AttrValueRank               = 15
	AttrArrayDimensions         = 16
	AttrAccessLevel             = 17
	AttrUserAccessLevel         = 18
	AttrMinimumSamplingInterval = 19
	AttrHistorizing             = 20
	AttrExecutable              = 21
	AttrUserExecutable          = 22
	AttrDataTypeDefinition      = 23
	AttrRolePermissions         = 24
	AttrUserRolePermissions     = 25
	AttrAccessRestrictions      = 26
	AttrAccessLevelEx           = 27
)

func (s *Server) checkOperations(n int) ua.StatusCode {
	if n == 0 {
		return ua.StatusBadNothingToDo
	}
	if n > s.cfg.MaxOperationsPerCall {
		return ua.StatusBadTooManyOperations
	}
	return 0
}

func (s *Server) read(sess *Session, r *ua.ReadRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.NodesToRead)); st != 0 {
		return fault(hdr, st)
	}
	if r.MaxAge < 0 {
		return fault(hdr, ua.StatusBadMaxAgeInvalid)
	}
	if r.TimestampsToReturn < ua.TimestampsToReturnSource || r.TimestampsToReturn > ua.TimestampsToReturnNeither {
		return fault(hdr, ua.StatusBadTimestampsToReturnInvalid)
	}
	ctx := ReadContext{Session: sess}
	results := make([]ua.DataValue, len(r.NodesToRead))
	for i, rv := range r.NodesToRead {
		results[i] = s.readAttribute(ctx, rv, r.TimestampsToReturn)
	}
	return &ua.ReadResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func applyTimestamps(dv ua.DataValue, ttr ua.TimestampsToReturn) ua.DataValue {
	switch ttr {
	case ua.TimestampsToReturnSource:
		dv.ServerTimestamp, dv.ServerPicoseconds = time.Time{}, 0
	case ua.TimestampsToReturnServer:
		dv.SourceTimestamp, dv.SourcePicoseconds = time.Time{}, 0
	case ua.TimestampsToReturnNeither:
		dv.ServerTimestamp, dv.ServerPicoseconds = time.Time{}, 0
		dv.SourceTimestamp, dv.SourcePicoseconds = time.Time{}, 0
	}
	return dv
}

func isDefaultBinary(q ua.QualifiedName) bool {
	return q.Name == "" || (q.NamespaceIndex == 0 && q.Name == "Default Binary")
}

func (s *Server) readAttribute(ctx ReadContext, rv ua.ReadValueId, ttr ua.TimestampsToReturn) ua.DataValue {
	n := s.as.Node(rv.NodeId)
	if n == nil {
		return ua.DataValue{Status: ua.StatusBadNodeIdUnknown}
	}
	if rv.AttributeId != AttrValue {
		if rv.IndexRange != "" {
			return ua.DataValue{Status: ua.StatusBadIndexRangeNoData}
		}
		if rv.DataEncoding.Name != "" {
			return ua.DataValue{Status: ua.StatusBadDataEncodingInvalid}
		}
		v, st := s.attributeValue(ctx, n, rv.AttributeId)
		return ua.DataValue{Value: v, Status: st}
	}
	if n.Class != ua.NodeClassVariable && n.Class != ua.NodeClassVariableType {
		return ua.DataValue{Status: ua.StatusBadAttributeIdInvalid}
	}
	if !isDefaultBinary(rv.DataEncoding) {
		return ua.DataValue{Status: ua.StatusBadDataEncodingUnsupported}
	}
	if n.Class == ua.NodeClassVariable {
		if n.AccessLevel&AccessCurrentRead == 0 {
			return ua.DataValue{Status: ua.StatusBadNotReadable}
		}
		if n.UserAccessLevel&AccessCurrentRead == 0 {
			return ua.DataValue{Status: ua.StatusBadUserAccessDenied}
		}
	}
	dv := s.as.readValue(n, ctx)
	if dv.ServerTimestamp.IsZero() {
		dv.ServerTimestamp = time.Now()
	}
	if rv.IndexRange != "" {
		nr, err := parseNumericRange(rv.IndexRange)
		if err != nil {
			return ua.DataValue{Status: ua.StatusBadIndexRangeInvalid}
		}
		v, st := nr.apply(dv.Value)
		if st != 0 {
			return ua.DataValue{Status: st}
		}
		dv.Value = v
	}
	return applyTimestamps(dv, ttr)
}

func (s *Server) attributeValue(ctx ReadContext, n *Node, attr uint32) (ua.Variant, ua.StatusCode) {
	c := n.Class
	isType := c == ua.NodeClassObjectType || c == ua.NodeClassVariableType || c == ua.NodeClassReferenceType || c == ua.NodeClassDataType
	isVar := c == ua.NodeClassVariable || c == ua.NodeClassVariableType
	switch attr {
	case AttrNodeId:
		return ua.NewVariant(n.ID), 0
	case AttrNodeClass:
		return ua.NewVariant(int32(n.Class)), 0
	case AttrBrowseName:
		return ua.NewVariant(n.BrowseName), 0
	case AttrDisplayName:
		return ua.NewVariant(n.DisplayName), 0
	case AttrDescription:
		return ua.NewVariant(n.Description), 0
	case AttrWriteMask:
		return ua.NewVariant(n.WriteMask), 0
	case AttrUserWriteMask:
		return ua.NewVariant(n.WriteMask), 0
	case AttrIsAbstract:
		if isType {
			return ua.NewVariant(n.IsAbstract), 0
		}
	case AttrSymmetric:
		if c == ua.NodeClassReferenceType {
			return ua.NewVariant(n.Symmetric), 0
		}
	case AttrInverseName:
		if c == ua.NodeClassReferenceType {
			return ua.NewVariant(n.InverseName), 0
		}
	case AttrContainsNoLoops:
		if c == ua.NodeClassView {
			return ua.NewVariant(n.ContainsNoLoops), 0
		}
	case AttrEventNotifier:
		if c == ua.NodeClassObject || c == ua.NodeClassView {
			return ua.NewVariant(n.EventNotifier), 0
		}
	case AttrDataType:
		if isVar {
			return ua.NewVariant(n.DataType), 0
		}
	case AttrValueRank:
		if isVar {
			return ua.NewVariant(n.ValueRank), 0
		}
	case AttrArrayDimensions:
		if isVar {
			if n.ArrayDimensions == nil {
				return ua.Variant{}, 0
			}
			return ua.NewVariant(n.ArrayDimensions), 0
		}
	case AttrAccessLevel:
		if c == ua.NodeClassVariable {
			return ua.NewVariant(n.AccessLevel), 0
		}
	case AttrUserAccessLevel:
		if c == ua.NodeClassVariable {
			return ua.NewVariant(n.UserAccessLevel), 0
		}
	case AttrAccessLevelEx:
		if c == ua.NodeClassVariable {
			return ua.NewVariant(uint32(n.AccessLevel)), 0
		}
	case AttrMinimumSamplingInterval:
		if c == ua.NodeClassVariable {
			return ua.NewVariant(n.MinimumSamplingInterval), 0
		}
	case AttrHistorizing:
		if c == ua.NodeClassVariable {
			return ua.NewVariant(n.Historizing), 0
		}
	case AttrExecutable, AttrUserExecutable:
		if c == ua.NodeClassMethod {
			return ua.NewVariant(n.Executable), 0
		}
	case AttrDataTypeDefinition:
		if c == ua.NodeClassDataType {
			if def := s.dataTypeDefinition(n); def != nil {
				return ua.NewVariant(def), 0
			}
			return ua.Variant{}, ua.StatusBadAttributeIdInvalid
		}
	case AttrRolePermissions, AttrUserRolePermissions, AttrAccessRestrictions:
		// Not configured: the attributes are optional and reported as absent.
		return ua.Variant{}, ua.StatusBadAttributeIdInvalid
	}
	return ua.Variant{}, ua.StatusBadAttributeIdInvalid
}

// dataTypeDefinition builds a StructureDefinition or EnumDefinition from the NodeSet definition.
func (s *Server) dataTypeDefinition(n *Node) ua.Structure {
	def := n.definition
	if def == nil {
		return nil
	}
	isEnum := s.as.IsSubtype(n.ID, DataTypeEnumeration) || def.IsOptionSet
	if isEnum {
		ed := &ua.EnumDefinition{}
		for i, f := range def.Fields {
			v := int64(i)
			if f.Value != nil {
				v = *f.Value
			}
			dn := firstText(f.DisplayName)
			if dn.Text == "" {
				dn = ua.NewLocalizedText(f.Name)
			}
			ed.Fields = append(ed.Fields, ua.EnumField{Value: v, DisplayName: dn, Description: firstText(f.Description), Name: f.Name})
		}
		return ed
	}
	sd := &ua.StructureDefinition{StructureType: ua.StructureTypeStructure}
	if sup, ok := s.as.SuperType(n.ID); ok {
		sd.BaseDataType = sup
	}
	for _, r := range n.References() {
		if r.IsForward && r.ReferenceType == RefHasEncoding {
			if t := s.as.Node(r.Target.NodeId); t != nil && t.BrowseName.Name == "Default Binary" {
				sd.DefaultEncodingId = t.ID
			}
		}
	}
	if def.IsUnion {
		sd.StructureType = ua.StructureTypeUnion
	}
	for i, f := range def.Fields {
		if f.IsOptional {
			sd.StructureType = ua.StructureTypeStructureWithOptionalFields
		}
		rank := int32(-1)
		if f.ValueRank != nil {
			rank = *f.ValueRank
		}
		sd.Fields = append(sd.Fields, ua.StructureField{
			Name: f.Name, Description: firstText(f.Description), DataType: def.fieldTypes[i],
			ValueRank: rank, ArrayDimensions: parseDims(f.ArrayDimensions), MaxStringLength: f.MaxStringLength,
			IsOptional: f.IsOptional,
		})
	}
	return sd
}

// --- Write ---

func (s *Server) write(sess *Session, r *ua.WriteRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.NodesToWrite)); st != 0 {
		return fault(hdr, st)
	}
	ctx := ReadContext{Session: sess}
	results := make([]ua.StatusCode, len(r.NodesToWrite))
	for i, w := range r.NodesToWrite {
		results[i] = s.writeAttribute(ctx, w)
	}
	return &ua.WriteResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func (s *Server) writeAttribute(ctx ReadContext, w ua.WriteValue) ua.StatusCode {
	n := s.as.Node(w.NodeId)
	if n == nil {
		return ua.StatusBadNodeIdUnknown
	}
	if w.AttributeId < AttrNodeId || w.AttributeId > AttrAccessLevelEx {
		return ua.StatusBadAttributeIdInvalid
	}
	if w.AttributeId != AttrValue {
		if _, st := s.attributeValue(ctx, n, w.AttributeId); st != 0 {
			return st
		}
		return ua.StatusBadNotWritable
	}
	if n.Class != ua.NodeClassVariable {
		if n.Class == ua.NodeClassVariableType {
			return ua.StatusBadNotWritable
		}
		return ua.StatusBadAttributeIdInvalid
	}
	if n.AccessLevel&AccessCurrentWrite == 0 {
		return ua.StatusBadNotWritable
	}
	if n.UserAccessLevel&AccessCurrentWrite == 0 {
		return ua.StatusBadUserAccessDenied
	}
	dv := w.Value
	if dv.ServerPicoseconds != 0 || dv.SourcePicoseconds != 0 {
		return ua.StatusBadWriteNotSupported
	}

	if w.IndexRange != "" {
		nr, err := parseNumericRange(w.IndexRange)
		if err != nil {
			return ua.StatusBadIndexRangeInvalid
		}
		cur := s.as.readValue(n, ctx)
		nv, st := nr.replace(cur.Value, dv.Value)
		if st != 0 {
			return st
		}
		dv.Value = nv
	}
	if st := s.checkValueType(n, dv.Value); st != 0 {
		return st
	}
	if dv.SourceTimestamp.IsZero() {
		dv.SourceTimestamp = time.Now()
	}
	dv.ServerTimestamp = time.Now()
	if n.OnWrite != nil {
		if st := n.OnWrite(ctx, dv); st.IsBad() {
			return st
		}
	}
	if err := s.as.SetDataValue(n.ID, dv); err != nil {
		return ua.StatusBadInternalError
	}
	return 0
}

// builtinOf returns the built-in type that encodes values of a data type, or
// TypeNull for abstract types that accept several built-in types.
func (s *Server) builtinOf(dt ua.NodeId) ua.TypeID {
	t := dt
	for i := 0; i < 32; i++ {
		if t.Namespace == 0 && t.Type == ua.IDNumeric {
			switch {
			case t.Numeric >= 1 && t.Numeric <= 25:
				if t.Numeric == id.BaseDataType {
					return ua.TypeNull
				}
				return ua.TypeID(t.Numeric)
			case t.Numeric == id.Enumeration:
				return ua.TypeInt32
			case t.Numeric == id.Number || t.Numeric == id.Integer || t.Numeric == id.UInteger || t.Numeric == id.Decimal:
				return ua.TypeNull
			}
		}
		sup, ok := s.as.SuperType(t)
		if !ok {
			return ua.TypeNull
		}
		t = sup
	}
	return ua.TypeNull
}

func isNumericType(t ua.TypeID) bool { return t >= ua.TypeSByte && t <= ua.TypeDouble }
func isIntegerType(t ua.TypeID) bool { return t >= ua.TypeSByte && t <= ua.TypeUInt64 }
func isUnsignedType(t ua.TypeID) bool {
	return t == ua.TypeByte || t == ua.TypeUInt16 || t == ua.TypeUInt32 || t == ua.TypeUInt64
}

func (s *Server) checkValueType(n *Node, v ua.Variant) ua.StatusCode {
	if v.IsNull() {
		return ua.StatusBadTypeMismatch
	}
	// Value rank.
	switch rank := n.ValueRank; {
	case rank == -1 && v.IsArray():
		return ua.StatusBadTypeMismatch
	case rank >= 1 && !v.IsArray():
		return ua.StatusBadTypeMismatch
	case rank > 1 && v.ValueRank() != rank:
		return ua.StatusBadTypeMismatch
	case rank == -3 && v.ValueRank() > 1:
		return ua.StatusBadTypeMismatch
	case rank == 0 && !v.IsArray():
		return ua.StatusBadTypeMismatch
	case rank == 1 && v.ValueRank() != 1:
		return ua.StatusBadTypeMismatch
	}
	// ArrayDimensions gives the maximum length of each dimension (0 = any).
	if v.IsArray() && len(n.ArrayDimensions) == int(v.ValueRank()) {
		dims := v.Dimensions()
		if dims == nil {
			dims = []int32{int32(v.ArrayLength())}
		}
		for i, max := range n.ArrayDimensions {
			if max != 0 && uint32(dims[i]) > max {
				return ua.StatusBadTypeMismatch
			}
		}
	}
	// Data type.
	dt := n.DataType
	if dt.Namespace == 0 && dt.Type == ua.IDNumeric {
		switch dt.Numeric {
		case id.BaseDataType:
			return 0
		case id.Number, id.Decimal:
			if isNumericType(v.Type()) {
				return 0
			}
			return ua.StatusBadTypeMismatch
		case id.Integer:
			if isIntegerType(v.Type()) && !isUnsignedType(v.Type()) {
				return 0
			}
			return ua.StatusBadTypeMismatch
		case id.UInteger:
			if isUnsignedType(v.Type()) {
				return 0
			}
			return ua.StatusBadTypeMismatch
		}
	}
	want := s.builtinOf(dt)
	if want == ua.TypeNull {
		// Abstract sub types of Number etc.
		if s.as.IsSubtype(dt, ua.NewNumericNodeId(0, id.Number)) && !isNumericType(v.Type()) {
			return ua.StatusBadTypeMismatch
		}
		return 0
	}
	got := v.Type()
	if want == got {
		if want == ua.TypeExtensionObject && !s.as.IsSubtype(dt, DataTypeStructure) {
			return 0
		}
		if want == ua.TypeExtensionObject && dt != DataTypeStructure {
			return s.checkStructureType(dt, v)
		}
		return 0
	}
	// ByteString and Byte[] are interchangeable (Part 3, 5.6.2).
	if (want == ua.TypeByteString && got == ua.TypeByte && v.IsArray()) ||
		(want == ua.TypeByte && got == ua.TypeByteString && n.ValueRank >= 1) {
		return 0
	}
	return ua.StatusBadTypeMismatch
}

func (s *Server) checkStructureType(dt ua.NodeId, v ua.Variant) ua.StatusCode {
	check := func(eo ua.ExtensionObject) bool {
		st, ok := eo.Value.(ua.Structure)
		if !ok {
			return true // unknown encodings are accepted as-is
		}
		return s.as.IsSubtype(st.DataTypeID(), dt)
	}
	switch x := v.Value().(type) {
	case ua.ExtensionObject:
		if !check(x) {
			return ua.StatusBadTypeMismatch
		}
	case []ua.ExtensionObject:
		for _, eo := range x {
			if !check(eo) {
				return ua.StatusBadTypeMismatch
			}
		}
	}
	return 0
}

// --- NumericRange (Part 4, 7.27) ---

type numericRange [][2]int

func parseNumericRange(s string) (numericRange, error) {
	var nr numericRange
	for _, dim := range strings.Split(s, ",") {
		var lo, hi int
		var err error
		if i := strings.IndexByte(dim, ':'); i >= 0 {
			lo, err = strconv.Atoi(dim[:i])
			if err != nil {
				return nil, err
			}
			hi, err = strconv.Atoi(dim[i+1:])
			if err != nil {
				return nil, err
			}
			if hi <= lo {
				return nil, strconv.ErrSyntax
			}
		} else {
			lo, err = strconv.Atoi(dim)
			if err != nil {
				return nil, err
			}
			hi = lo
		}
		if lo < 0 {
			return nil, strconv.ErrSyntax
		}
		nr = append(nr, [2]int{lo, hi})
	}
	return nr, nil
}

func (nr numericRange) apply(v ua.Variant) (ua.Variant, ua.StatusCode) {
	if len(nr) != 1 {
		return ua.Variant{}, ua.StatusBadIndexRangeInvalid
	}
	lo, hi := nr[0][0], nr[0][1]
	val := v.Value()
	if !v.IsArray() {
		switch x := val.(type) {
		case string:
			if lo >= len(x) {
				return ua.Variant{}, ua.StatusBadIndexRangeNoData
			}
			return ua.NewVariant(x[lo:min(hi+1, len(x))]), 0
		case []byte:
			if lo >= len(x) {
				return ua.Variant{}, ua.StatusBadIndexRangeNoData
			}
			return ua.NewVariant(x[lo:min(hi+1, len(x))]), 0
		}
		return ua.Variant{}, ua.StatusBadIndexRangeNoData
	}
	rv := reflect.ValueOf(val)
	if lo >= rv.Len() {
		return ua.Variant{}, ua.StatusBadIndexRangeNoData
	}
	sub := rv.Slice(lo, min(hi+1, rv.Len())).Interface()
	if v.Type() == ua.TypeByte {
		return ua.NewByteArrayVariant(sub.([]byte)), 0
	}
	out, err := ua.TryVariant(sub)
	if err != nil {
		return ua.Variant{}, ua.StatusBadIndexRangeInvalid
	}
	return out, 0
}

func (nr numericRange) replace(cur, part ua.Variant) (ua.Variant, ua.StatusCode) {
	if len(nr) != 1 || !cur.IsArray() || !part.IsArray() || cur.Type() != part.Type() {
		return ua.Variant{}, ua.StatusBadIndexRangeInvalid
	}
	lo, hi := nr[0][0], nr[0][1]
	cv := reflect.ValueOf(cur.Value())
	pv := reflect.ValueOf(part.Value())
	if hi >= cv.Len() {
		return ua.Variant{}, ua.StatusBadIndexRangeNoData
	}
	if pv.Len() != hi-lo+1 {
		return ua.Variant{}, ua.StatusBadIndexRangeInvalid
	}
	nv := reflect.MakeSlice(cv.Type(), cv.Len(), cv.Len())
	reflect.Copy(nv, cv)
	reflect.Copy(nv.Slice(lo, hi+1), pv)
	if cur.Type() == ua.TypeByte {
		return ua.NewByteArrayVariant(nv.Interface().([]byte)), 0
	}
	out, err := ua.TryVariant(nv.Interface())
	if err != nil {
		return ua.Variant{}, ua.StatusBadIndexRangeInvalid
	}
	return out, 0
}
