package server

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/bamchoh/uastack/ua"
)

//go:embed ns0/Opc.Ua.NodeSet2.xml.gz
var ns0NodeSet []byte

type xmlNodeSet struct {
	NamespaceUris []string    `xml:"NamespaceUris>Uri"`
	Aliases       []xmlAlias  `xml:"Aliases>Alias"`
	Nodes         []xmlUANode `xml:",any"`
}

type xmlAlias struct {
	Alias string `xml:"Alias,attr"`
	Value string `xml:",chardata"`
}

type xmlText struct {
	Locale string `xml:"Locale,attr"`
	Text   string `xml:",chardata"`
}

type xmlRef struct {
	ReferenceType string `xml:"ReferenceType,attr"`
	IsForward     string `xml:"IsForward,attr"`
	Target        string `xml:",chardata"`
}

type xmlInner struct {
	Inner []byte `xml:",innerxml"`
}

type xmlDefField struct {
	Name            string    `xml:"Name,attr"`
	DataType        string    `xml:"DataType,attr"`
	ValueRank       *int32    `xml:"ValueRank,attr"`
	ArrayDimensions string    `xml:"ArrayDimensions,attr"`
	MaxStringLength uint32    `xml:"MaxStringLength,attr"`
	Value           *int64    `xml:"Value,attr"`
	IsOptional      bool      `xml:"IsOptional,attr"`
	DisplayName     []xmlText `xml:"DisplayName"`
	Description     []xmlText `xml:"Description"`
}

type xmlDefinition struct {
	Name        string        `xml:"Name,attr"`
	IsUnion     bool          `xml:"IsUnion,attr"`
	IsOptionSet bool          `xml:"IsOptionSet,attr"`
	Fields      []xmlDefField `xml:"Field"`
	// resolved data type ids of the fields
	fieldTypes []ua.NodeId
}

type xmlUANode struct {
	XMLName                 xml.Name
	NodeID                  string         `xml:"NodeId,attr"`
	BrowseName              string         `xml:"BrowseName,attr"`
	WriteMask               uint32         `xml:"WriteMask,attr"`
	DisplayName             []xmlText      `xml:"DisplayName"`
	Description             []xmlText      `xml:"Description"`
	References              []xmlRef       `xml:"References>Reference"`
	IsAbstract              bool           `xml:"IsAbstract,attr"`
	Symmetric               bool           `xml:"Symmetric,attr"`
	InverseName             []xmlText      `xml:"InverseName"`
	EventNotifier           byte           `xml:"EventNotifier,attr"`
	ContainsNoLoops         bool           `xml:"ContainsNoLoops,attr"`
	DataType                string         `xml:"DataType,attr"`
	ValueRank               *int32         `xml:"ValueRank,attr"`
	ArrayDimensions         string         `xml:"ArrayDimensions,attr"`
	AccessLevel             *byte          `xml:"AccessLevel,attr"`
	MinimumSamplingInterval float64        `xml:"MinimumSamplingInterval,attr"`
	Historizing             bool           `xml:"Historizing,attr"`
	Executable              *bool          `xml:"Executable,attr"`
	Value                   *xmlInner      `xml:"Value"`
	Definition              *xmlDefinition `xml:"Definition"`
}

// nodeSetLoader maps the namespace indexes and aliases of one NodeSet file.
type nodeSetLoader struct {
	as      *AddressSpace
	nsMap   []uint16
	aliases map[string]string
}

func loadNS0(as *AddressSpace) error {
	zr, err := gzip.NewReader(bytes.NewReader(ns0NodeSet))
	if err != nil {
		return err
	}
	return as.LoadNodeSet(zr)
}

// LoadNodeSet loads a UANodeSet2 XML document into the address space. The
// namespaces of the document are registered in the server namespace table.
func (a *AddressSpace) LoadNodeSet(r io.Reader) error {
	var doc xmlNodeSet
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return fmt.Errorf("server: parse nodeset: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	l := &nodeSetLoader{as: a, nsMap: []uint16{0}, aliases: map[string]string{}}
	for _, u := range doc.NamespaceUris {
		l.nsMap = append(l.nsMap, a.registerNamespaceLocked(u))
	}
	for _, al := range doc.Aliases {
		l.aliases[al.Alias] = strings.TrimSpace(al.Value)
	}
	// First pass: create nodes. Second pass: references (both directions).
	type pending struct {
		n    *Node
		refs []Reference
	}
	var all []pending
	for i := range doc.Nodes {
		xn := &doc.Nodes[i]
		n, refs, err := l.buildNode(xn)
		if err != nil {
			return err
		}
		if n == nil {
			continue
		}
		if old, ok := a.nodes[n.ID]; ok {
			// Later definitions replace earlier ones but keep references.
			n.refs = old.refs
		}
		a.nodes[n.ID] = n
		all = append(all, pending{n, refs})
	}
	for _, p := range all {
		for _, r := range p.refs {
			a.addReferenceLocked(p.n.ID, r.ReferenceType, r.Target, r.IsForward)
		}
	}
	// Values are decoded after all nodes exist (no dependency today, but keeps order simple).
	for i := range doc.Nodes {
		xn := &doc.Nodes[i]
		if xn.Value == nil {
			continue
		}
		nid, err := l.nodeID(xn.NodeID)
		if err != nil {
			continue
		}
		n := a.nodes[nid]
		v, err := l.decodeValue(xn.Value.Inner)
		if err != nil {
			return fmt.Errorf("server: node %s: value: %w", xn.NodeID, err)
		}
		n.value = ua.DataValue{Value: v, ServerTimestamp: time.Now()}
	}
	return nil
}

func (l *nodeSetLoader) nodeID(s string) (ua.NodeId, error) {
	s = strings.TrimSpace(s)
	if v, ok := l.aliases[s]; ok {
		s = v
	}
	n, err := ua.ParseNodeId(s)
	if err != nil {
		return n, err
	}
	if int(n.Namespace) < len(l.nsMap) {
		n.Namespace = l.nsMap[n.Namespace]
	} else {
		return n, fmt.Errorf("namespace index %d not declared", n.Namespace)
	}
	return n, nil
}

func (l *nodeSetLoader) qname(s string) ua.QualifiedName {
	if i := strings.IndexByte(s, ':'); i > 0 {
		if ns, err := strconv.Atoi(s[:i]); err == nil && ns < len(l.nsMap) {
			return ua.QualifiedName{NamespaceIndex: l.nsMap[ns], Name: s[i+1:]}
		}
	}
	return ua.QualifiedName{Name: s}
}

func firstText(t []xmlText) ua.LocalizedText {
	if len(t) == 0 {
		return ua.LocalizedText{}
	}
	return ua.LocalizedText{Locale: t[0].Locale, Text: strings.TrimSpace(t[0].Text)}
}

func parseDims(s string) []uint32 {
	if s == "" {
		return nil
	}
	var out []uint32
	for _, p := range strings.Split(s, ",") {
		v, _ := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
		out = append(out, uint32(v))
	}
	return out
}

func (l *nodeSetLoader) buildNode(xn *xmlUANode) (*Node, []Reference, error) {
	var class ua.NodeClass
	switch xn.XMLName.Local {
	case "UAObject":
		class = ua.NodeClassObject
	case "UAVariable":
		class = ua.NodeClassVariable
	case "UAMethod":
		class = ua.NodeClassMethod
	case "UAObjectType":
		class = ua.NodeClassObjectType
	case "UAVariableType":
		class = ua.NodeClassVariableType
	case "UAReferenceType":
		class = ua.NodeClassReferenceType
	case "UADataType":
		class = ua.NodeClassDataType
	case "UAView":
		class = ua.NodeClassView
	default:
		return nil, nil, nil
	}
	nid, err := l.nodeID(xn.NodeID)
	if err != nil {
		return nil, nil, fmt.Errorf("server: node id %q: %w", xn.NodeID, err)
	}
	n := &Node{
		ID: nid, Class: class, BrowseName: l.qname(xn.BrowseName),
		DisplayName: firstText(xn.DisplayName), Description: firstText(xn.Description),
		WriteMask: xn.WriteMask, IsAbstract: xn.IsAbstract, Symmetric: xn.Symmetric,
		InverseName: firstText(xn.InverseName), EventNotifier: xn.EventNotifier,
		ContainsNoLoops: xn.ContainsNoLoops, MinimumSamplingInterval: xn.MinimumSamplingInterval,
		Historizing: xn.Historizing, ArrayDimensions: parseDims(xn.ArrayDimensions),
	}
	if n.DisplayName.Text == "" {
		n.DisplayName = ua.NewLocalizedText(n.BrowseName.Name)
	}
	if class == ua.NodeClassVariable || class == ua.NodeClassVariableType {
		n.DataType = DataTypeBaseDataType
		if xn.DataType != "" {
			if dt, err := l.nodeID(xn.DataType); err == nil {
				n.DataType = dt
			}
		}
		n.ValueRank = -1
		if xn.ValueRank != nil {
			n.ValueRank = *xn.ValueRank
		}
		n.AccessLevel = AccessCurrentRead
		if xn.AccessLevel != nil {
			n.AccessLevel = *xn.AccessLevel
		}
		n.UserAccessLevel = n.AccessLevel
	}
	if class == ua.NodeClassMethod {
		n.Executable = true
		if xn.Executable != nil {
			n.Executable = *xn.Executable
		}
	}
	if class == ua.NodeClassDataType && xn.Definition != nil {
		def := xn.Definition
		def.fieldTypes = make([]ua.NodeId, len(def.Fields))
		for i, f := range def.Fields {
			if f.DataType != "" {
				def.fieldTypes[i], _ = l.nodeID(f.DataType)
			} else {
				def.fieldTypes[i] = DataTypeBaseDataType
			}
		}
		n.definition = def
	}
	var refs []Reference
	for _, r := range xn.References {
		rt, err := l.nodeID(r.ReferenceType)
		if err != nil {
			return nil, nil, fmt.Errorf("server: node %s: reference type %q: %w", xn.NodeID, r.ReferenceType, err)
		}
		tgt, err := l.nodeID(r.Target)
		if err != nil {
			return nil, nil, fmt.Errorf("server: node %s: reference target %q: %w", xn.NodeID, r.Target, err)
		}
		refs = append(refs, Reference{ReferenceType: rt, Target: ua.NewExpandedNodeId(tgt), IsForward: r.IsForward != "false"})
	}
	return n, refs, nil
}

// --- XML value decoding (Part 6, 5.3) ---

type xelem struct {
	name     string
	text     string
	children []*xelem
}

func (e *xelem) child(name string) *xelem {
	for _, c := range e.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

func (e *xelem) childText(name string) string {
	if c := e.child(name); c != nil {
		return strings.TrimSpace(c.text)
	}
	return ""
}

func parseXElems(b []byte) ([]*xelem, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	root := &xelem{}
	stack := []*xelem{root}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			e := &xelem{name: t.Name.Local}
			top := stack[len(stack)-1]
			top.children = append(top.children, e)
			stack = append(stack, e)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			top := stack[len(stack)-1]
			top.text += string(t)
		}
	}
	return root.children, nil
}

func (l *nodeSetLoader) decodeValue(inner []byte) (ua.Variant, error) {
	elems, err := parseXElems(inner)
	if err != nil {
		return ua.Variant{}, err
	}
	if len(elems) == 0 {
		return ua.Variant{}, nil
	}
	return l.variantFromXML(elems[0])
}

var xmlScalarTypes = map[string]ua.TypeID{
	"Boolean": ua.TypeBoolean, "SByte": ua.TypeSByte, "Byte": ua.TypeByte, "Int16": ua.TypeInt16,
	"UInt16": ua.TypeUInt16, "Int32": ua.TypeInt32, "UInt32": ua.TypeUInt32, "Int64": ua.TypeInt64,
	"UInt64": ua.TypeUInt64, "Float": ua.TypeFloat, "Double": ua.TypeDouble, "String": ua.TypeString,
	"DateTime": ua.TypeDateTime, "Guid": ua.TypeGuid, "ByteString": ua.TypeByteString,
	"XmlElement": ua.TypeXmlElement, "NodeId": ua.TypeNodeId, "ExpandedNodeId": ua.TypeExpandedNodeId,
	"StatusCode": ua.TypeStatusCode, "QualifiedName": ua.TypeQualifiedName,
	"LocalizedText": ua.TypeLocalizedText, "ExtensionObject": ua.TypeExtensionObject,
	"DataValue": ua.TypeDataValue, "Variant": ua.TypeVariant,
}

func (l *nodeSetLoader) variantFromXML(e *xelem) (ua.Variant, error) {
	if strings.HasPrefix(e.name, "ListOf") {
		t, ok := xmlScalarTypes[strings.TrimPrefix(e.name, "ListOf")]
		if !ok {
			return ua.Variant{}, fmt.Errorf("unsupported value type %s", e.name)
		}
		vals := make([]any, 0, len(e.children))
		for _, c := range e.children {
			v, err := l.scalarFromXML(t, c)
			if err != nil {
				return ua.Variant{}, err
			}
			vals = append(vals, v)
		}
		return makeArrayVariant(t, vals)
	}
	t, ok := xmlScalarTypes[e.name]
	if !ok {
		return ua.Variant{}, fmt.Errorf("unsupported value type %s", e.name)
	}
	v, err := l.scalarFromXML(t, e)
	if err != nil {
		return ua.Variant{}, err
	}
	if t == ua.TypeVariant {
		return v.(ua.Variant), nil
	}
	return ua.TryVariant(v)
}

func makeArrayVariant(t ua.TypeID, vals []any) (ua.Variant, error) {
	// Build a typed slice through reflection on the scalar type.
	if t == ua.TypeByte {
		b := make([]byte, len(vals))
		for i, v := range vals {
			b[i] = v.(byte)
		}
		return ua.NewByteArrayVariant(b), nil
	}
	sample, err := ua.TryVariant(zeroOf(t))
	if err != nil {
		return ua.Variant{}, err
	}
	st := reflect.TypeOf(sample.Value())
	if t == ua.TypeVariant {
		st = reflect.TypeOf(ua.Variant{})
	}
	s := reflect.MakeSlice(reflect.SliceOf(st), len(vals), len(vals))
	for i, v := range vals {
		s.Index(i).Set(reflect.ValueOf(v))
	}
	return ua.TryVariant(s.Interface())
}

func zeroOf(t ua.TypeID) any {
	switch t {
	case ua.TypeBoolean:
		return false
	case ua.TypeSByte:
		return int8(0)
	case ua.TypeInt16:
		return int16(0)
	case ua.TypeUInt16:
		return uint16(0)
	case ua.TypeInt32:
		return int32(0)
	case ua.TypeUInt32:
		return uint32(0)
	case ua.TypeInt64:
		return int64(0)
	case ua.TypeUInt64:
		return uint64(0)
	case ua.TypeFloat:
		return float32(0)
	case ua.TypeDouble:
		return float64(0)
	case ua.TypeString:
		return ""
	case ua.TypeDateTime:
		return time.Time{}
	case ua.TypeGuid:
		return ua.Guid{}
	case ua.TypeByteString:
		return []byte{}
	case ua.TypeXmlElement:
		return ua.XmlElement("")
	case ua.TypeNodeId:
		return ua.NodeId{}
	case ua.TypeExpandedNodeId:
		return ua.ExpandedNodeId{}
	case ua.TypeStatusCode:
		return ua.StatusCode(0)
	case ua.TypeQualifiedName:
		return ua.QualifiedName{}
	case ua.TypeLocalizedText:
		return ua.LocalizedText{}
	case ua.TypeExtensionObject:
		return ua.ExtensionObject{}
	case ua.TypeDataValue:
		return ua.DataValue{}
	}
	return nil
}

func (l *nodeSetLoader) scalarFromXML(t ua.TypeID, e *xelem) (any, error) {
	txt := strings.TrimSpace(e.text)
	switch t {
	case ua.TypeBoolean:
		return txt == "true" || txt == "1", nil
	case ua.TypeSByte:
		v, err := strconv.ParseInt(txt, 10, 8)
		return int8(v), err
	case ua.TypeByte:
		v, err := strconv.ParseUint(txt, 10, 8)
		return byte(v), err
	case ua.TypeInt16:
		v, err := strconv.ParseInt(txt, 10, 16)
		return int16(v), err
	case ua.TypeUInt16:
		v, err := strconv.ParseUint(txt, 10, 16)
		return uint16(v), err
	case ua.TypeInt32:
		v, err := strconv.ParseInt(txt, 10, 32)
		return int32(v), err
	case ua.TypeUInt32:
		v, err := strconv.ParseUint(txt, 10, 32)
		return uint32(v), err
	case ua.TypeInt64:
		v, err := strconv.ParseInt(txt, 10, 64)
		return v, err
	case ua.TypeUInt64:
		v, err := strconv.ParseUint(txt, 10, 64)
		return v, err
	case ua.TypeFloat:
		v, err := parseXMLFloat(txt, 32)
		return float32(v), err
	case ua.TypeDouble:
		return parseXMLFloat(txt, 64)
	case ua.TypeString:
		return e.text, nil
	case ua.TypeDateTime:
		if txt == "" {
			return time.Time{}, nil
		}
		return time.Parse(time.RFC3339Nano, txt)
	case ua.TypeGuid:
		s := e.childText("String")
		if s == "" {
			s = txt
		}
		return ua.ParseGuid(s)
	case ua.TypeByteString:
		return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(txt), ""))
	case ua.TypeXmlElement:
		return ua.XmlElement(txt), nil
	case ua.TypeNodeId:
		s := e.childText("Identifier")
		if s == "" {
			return ua.NodeId{}, nil
		}
		return l.nodeID(s)
	case ua.TypeExpandedNodeId:
		s := e.childText("Identifier")
		if s == "" {
			return ua.ExpandedNodeId{}, nil
		}
		n, err := l.nodeID(s)
		return ua.NewExpandedNodeId(n), err
	case ua.TypeStatusCode:
		v, err := strconv.ParseUint(e.childText("Code"), 0, 32)
		return ua.StatusCode(v), err
	case ua.TypeQualifiedName:
		ns, _ := strconv.Atoi(e.childText("NamespaceIndex"))
		if ns < len(l.nsMap) {
			ns = int(l.nsMap[ns])
		}
		return ua.QualifiedName{NamespaceIndex: uint16(ns), Name: e.childText("Name")}, nil
	case ua.TypeLocalizedText:
		return ua.LocalizedText{Locale: e.childText("Locale"), Text: e.childText("Text")}, nil
	case ua.TypeExtensionObject:
		return l.extensionObjectFromXML(e)
	case ua.TypeVariant:
		if len(e.children) > 0 && len(e.children[0].children) > 0 {
			return l.variantFromXML(e.children[0].children[0])
		}
		return ua.Variant{}, nil
	case ua.TypeDataValue:
		var dv ua.DataValue
		if v := e.child("Value"); v != nil && len(v.children) > 0 {
			vv, err := l.variantFromXML(v.children[0])
			if err != nil {
				return nil, err
			}
			dv.Value = vv
		}
		return dv, nil
	}
	return nil, fmt.Errorf("unsupported type %s", t)
}

func parseXMLFloat(s string, bits int) (float64, error) {
	switch s {
	case "INF":
		return mathInf(1), nil
	case "-INF":
		return mathInf(-1), nil
	case "NaN":
		return mathNaN(), nil
	}
	return strconv.ParseFloat(s, bits)
}

func (l *nodeSetLoader) extensionObjectFromXML(e *xelem) (ua.ExtensionObject, error) {
	body := e.child("Body")
	if body == nil || len(body.children) == 0 {
		return ua.ExtensionObject{}, nil
	}
	be := body.children[0]
	s := ua.NewStructureByName(be.name)
	if s == nil {
		// Unknown structure: keep the XML body.
		var typeID ua.NodeId
		if t := e.child("TypeId"); t != nil {
			typeID, _ = l.nodeID(t.childText("Identifier"))
		}
		return ua.ExtensionObject{TypeID: ua.NewExpandedNodeId(typeID), Value: ua.XmlElement(be.text)}, nil
	}
	if err := l.structFromXML(reflect.ValueOf(s).Elem(), be); err != nil {
		return ua.ExtensionObject{}, fmt.Errorf("%s: %w", be.name, err)
	}
	return ua.NewExtensionObject(s), nil
}

var (
	rtNodeId        = reflect.TypeOf(ua.NodeId{})
	rtExpandedNode  = reflect.TypeOf(ua.ExpandedNodeId{})
	rtQualifiedName = reflect.TypeOf(ua.QualifiedName{})
	rtLocalizedText = reflect.TypeOf(ua.LocalizedText{})
	rtVariant       = reflect.TypeOf(ua.Variant{})
	rtExtObj        = reflect.TypeOf(ua.ExtensionObject{})
	rtTime          = reflect.TypeOf(time.Time{})
	rtGuid          = reflect.TypeOf(ua.Guid{})
	rtStatus        = reflect.TypeOf(ua.StatusCode(0))
	rtDataValue     = reflect.TypeOf(ua.DataValue{})
)

// structFromXML fills a generated structure from its XML encoding.
func (l *nodeSetLoader) structFromXML(v reflect.Value, e *xelem) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		c := e.child(f.Name)
		if c == nil {
			continue
		}
		if err := l.fieldFromXML(v.Field(i), c); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
	}
	return nil
}

func (l *nodeSetLoader) fieldFromXML(fv reflect.Value, c *xelem) error {
	ft := fv.Type()
	var tid ua.TypeID = 255
	switch ft {
	case rtNodeId:
		tid = ua.TypeNodeId
	case rtExpandedNode:
		tid = ua.TypeExpandedNodeId
	case rtQualifiedName:
		tid = ua.TypeQualifiedName
	case rtLocalizedText:
		tid = ua.TypeLocalizedText
	case rtExtObj:
		tid = ua.TypeExtensionObject
	case rtTime:
		tid = ua.TypeDateTime
	case rtGuid:
		tid = ua.TypeGuid
	case rtStatus:
		tid = ua.TypeStatusCode
	case rtDataValue:
		tid = ua.TypeDataValue
	case rtVariant:
		if len(c.children) == 0 {
			return nil
		}
		vv, err := l.variantFromXML(c.children[0])
		if err != nil {
			return err
		}
		fv.Set(reflect.ValueOf(vv))
		return nil
	}
	if tid != 255 {
		x, err := l.scalarFromXML(tid, c)
		if err != nil {
			return err
		}
		fv.Set(reflect.ValueOf(x))
		return nil
	}
	txt := strings.TrimSpace(c.text)
	switch ft.Kind() {
	case reflect.Bool:
		fv.SetBool(txt == "true" || txt == "1")
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Enumerations are encoded as "Name_Value".
		if i := strings.LastIndexByte(txt, '_'); i >= 0 {
			txt = txt[i+1:]
		}
		n, err := strconv.ParseInt(txt, 10, 64)
		if err != nil {
			return err
		}
		fv.SetInt(n)
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(txt, 10, 64)
		if err != nil {
			return err
		}
		fv.SetUint(n)
	case reflect.Float32, reflect.Float64:
		f, err := parseXMLFloat(txt, 64)
		if err != nil {
			return err
		}
		fv.SetFloat(f)
	case reflect.String:
		fv.SetString(c.text)
	case reflect.Struct:
		return l.structFromXML(fv, c)
	case reflect.Slice:
		if ft.Elem().Kind() == reflect.Uint8 {
			b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(txt), ""))
			if err != nil {
				return err
			}
			fv.SetBytes(b)
			return nil
		}
		s := reflect.MakeSlice(ft, len(c.children), len(c.children))
		for i, cc := range c.children {
			if err := l.fieldFromXML(s.Index(i), cc); err != nil {
				return err
			}
		}
		fv.Set(s)
	default:
		return fmt.Errorf("unsupported field kind %s", ft.Kind())
	}
	return nil
}
