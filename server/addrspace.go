package server

import (
	"fmt"
	"sync"
	"time"

	"github.com/bamchoh/uaserver/ua"
	"github.com/bamchoh/uaserver/ua/id"
)

// Reference is a reference from a node to another node.
type Reference struct {
	ReferenceType ua.NodeId
	Target        ua.ExpandedNodeId
	IsForward     bool
}

// ReadContext describes the caller of a read or write callback.
type ReadContext struct {
	Session *Session // nil for internal reads (e.g. sampling without a session)
}

// Node is a node in the address space. Fields must only be modified through
// the AddressSpace methods (or before the node is added).
type Node struct {
	ID          ua.NodeId
	Class       ua.NodeClass
	BrowseName  ua.QualifiedName
	DisplayName ua.LocalizedText
	Description ua.LocalizedText
	WriteMask   uint32

	// Type nodes.
	IsAbstract bool
	// ReferenceType nodes.
	Symmetric   bool
	InverseName ua.LocalizedText
	// View nodes.
	ContainsNoLoops bool
	// Object and View nodes.
	EventNotifier byte

	// Variable and VariableType nodes.
	DataType                ua.NodeId
	ValueRank               int32
	ArrayDimensions         []uint32
	AccessLevel             byte
	UserAccessLevel         byte
	MinimumSamplingInterval float64
	Historizing             bool

	// Method nodes.
	Executable bool

	// DataType nodes: the definition parsed from a NodeSet (built lazily).
	definition *xmlDefinition

	// OnRead, if set, provides the value of a Variable.
	OnRead func(ctx ReadContext) ua.DataValue
	// OnWrite, if set, is called before a value is written. Returning a bad
	// status rejects the write.
	OnWrite func(ctx ReadContext, v ua.DataValue) ua.StatusCode
	// OnCall implements a Method.
	OnCall func(ctx ReadContext, objectID ua.NodeId, inputs []ua.Variant) ([]ua.Variant, ua.StatusCode)

	value ua.DataValue
	refs  []Reference
}

// References returns a copy of the node references.
func (n *Node) References() []Reference { return append([]Reference(nil), n.refs...) }

// AddressSpace holds the nodes of the server.
type AddressSpace struct {
	mu         sync.RWMutex
	nodes      map[ua.NodeId]*Node
	namespaces []string
	// subtype cache: reference/data type id -> super type id
	superTypes map[ua.NodeId]ua.NodeId
}

func newAddressSpace(appURI string) *AddressSpace {
	return &AddressSpace{
		nodes:      map[ua.NodeId]*Node{},
		namespaces: []string{"http://opcfoundation.org/UA/", appURI},
		superTypes: map[ua.NodeId]ua.NodeId{},
	}
}

// NamespaceArray returns the server namespace table.
func (a *AddressSpace) NamespaceArray() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]string(nil), a.namespaces...)
}

// RegisterNamespace adds a namespace URI and returns its index. If the URI is
// already registered its existing index is returned.
func (a *AddressSpace) RegisterNamespace(uri string) uint16 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.registerNamespaceLocked(uri)
}

func (a *AddressSpace) registerNamespaceLocked(uri string) uint16 {
	for i, u := range a.namespaces {
		if u == uri {
			return uint16(i)
		}
	}
	a.namespaces = append(a.namespaces, uri)
	return uint16(len(a.namespaces) - 1)
}

// NamespaceIndex returns the index of a namespace URI.
func (a *AddressSpace) NamespaceIndex(uri string) (uint16, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for i, u := range a.namespaces {
		if u == uri {
			return uint16(i), true
		}
	}
	return 0, false
}

// Node returns the node with the given id or nil.
func (a *AddressSpace) Node(nid ua.NodeId) *Node {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.nodes[nid]
}

// AddNode adds a node. References of the node are added in both directions.
func (a *AddressSpace) AddNode(n *Node) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addNodeLocked(n)
}

func (a *AddressSpace) addNodeLocked(n *Node) error {
	if n.ID.IsNull() {
		return fmt.Errorf("server: node id is null")
	}
	if _, ok := a.nodes[n.ID]; ok {
		return fmt.Errorf("server: node %s already exists", n.ID)
	}
	refs := n.refs
	n.refs = nil
	a.nodes[n.ID] = n
	for _, r := range refs {
		a.addReferenceLocked(n.ID, r.ReferenceType, r.Target, r.IsForward)
	}
	return nil
}

// AddReference adds a reference and its inverse.
func (a *AddressSpace) AddReference(source, refType ua.NodeId, target ua.ExpandedNodeId, forward bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.addReferenceLocked(source, refType, target, forward)
}

func (a *AddressSpace) addReferenceLocked(source, refType ua.NodeId, target ua.ExpandedNodeId, forward bool) {
	src := a.nodes[source]
	if src == nil {
		return
	}
	if !hasRef(src.refs, refType, target, forward) {
		src.refs = append(src.refs, Reference{ReferenceType: refType, Target: target, IsForward: forward})
	}
	if refType == ua.NewNumericNodeId(0, id.HasSubtype) && target.IsLocal() && target.NamespaceURI == "" {
		if forward {
			a.superTypes[target.NodeId] = source
		} else {
			a.superTypes[source] = target.NodeId
		}
	}
	if target.IsLocal() && target.NamespaceURI == "" {
		if dst := a.nodes[target.NodeId]; dst != nil {
			back := ua.NewExpandedNodeId(source)
			if !hasRef(dst.refs, refType, back, !forward) {
				dst.refs = append(dst.refs, Reference{ReferenceType: refType, Target: back, IsForward: !forward})
			}
		}
	}
}

func hasRef(refs []Reference, t ua.NodeId, target ua.ExpandedNodeId, fwd bool) bool {
	for _, r := range refs {
		if r.IsForward == fwd && r.ReferenceType == t && r.Target == target {
			return true
		}
	}
	return false
}

// DeleteNode removes a node and all references pointing to it.
func (a *AddressSpace) DeleteNode(nid ua.NodeId) {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := a.nodes[nid]
	if n == nil {
		return
	}
	delete(a.nodes, nid)
	for _, r := range n.refs {
		if dst := a.nodes[r.Target.NodeId]; dst != nil && r.Target.IsLocal() {
			kept := dst.refs[:0]
			for _, rr := range dst.refs {
				if !(rr.Target.NodeId == nid && rr.Target.IsLocal()) {
					kept = append(kept, rr)
				}
			}
			dst.refs = kept
		}
	}
}

// SuperType returns the super type of a type node.
func (a *AddressSpace) SuperType(t ua.NodeId) (ua.NodeId, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s, ok := a.superTypes[t]
	return s, ok
}

// IsSubtype reports whether t equals base or is a subtype of it.
func (a *AddressSpace) IsSubtype(t, base ua.NodeId) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.isSubtypeLocked(t, base)
}

func (a *AddressSpace) isSubtypeLocked(t, base ua.NodeId) bool {
	for i := 0; i < 64; i++ {
		if t == base {
			return true
		}
		s, ok := a.superTypes[t]
		if !ok {
			return false
		}
		t = s
	}
	return false
}

// SetValue sets the value of a variable. The source and server timestamps
// default to now.
func (a *AddressSpace) SetValue(nid ua.NodeId, v ua.Variant) error {
	now := time.Now()
	return a.SetDataValue(nid, ua.DataValue{Value: v, SourceTimestamp: now, ServerTimestamp: now})
}

// SetDataValue sets value, status and timestamps of a variable.
func (a *AddressSpace) SetDataValue(nid ua.NodeId, dv ua.DataValue) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := a.nodes[nid]
	if n == nil {
		return ua.StatusBadNodeIdUnknown
	}
	if n.Class != ua.NodeClassVariable && n.Class != ua.NodeClassVariableType {
		return ua.StatusBadAttributeIdInvalid
	}
	if dv.ServerTimestamp.IsZero() {
		dv.ServerTimestamp = time.Now()
	}
	n.value = dv
	return nil
}

// Value returns the current value of a variable (calling OnRead if set).
func (a *AddressSpace) Value(nid ua.NodeId) (ua.DataValue, error) {
	a.mu.RLock()
	n := a.nodes[nid]
	if n == nil {
		a.mu.RUnlock()
		return ua.DataValue{}, ua.StatusBadNodeIdUnknown
	}
	onRead, v := n.OnRead, n.value
	a.mu.RUnlock()
	if onRead != nil {
		return onRead(ReadContext{}), nil
	}
	return v, nil
}

func (a *AddressSpace) readValue(n *Node, ctx ReadContext) ua.DataValue {
	a.mu.RLock()
	onRead, v := n.OnRead, n.value
	a.mu.RUnlock()
	if onRead != nil {
		return onRead(ctx)
	}
	return v
}

// TypeDefinition returns the type definition of an object or variable.
func (a *AddressSpace) typeDefinitionLocked(n *Node) ua.ExpandedNodeId {
	htd := ua.NewNumericNodeId(0, id.HasTypeDefinition)
	for _, r := range n.refs {
		if r.IsForward && r.ReferenceType == htd {
			return r.Target
		}
	}
	return ua.ExpandedNodeId{}
}

// --- convenience builders ---

// Well known ids.
var (
	RootFolder           = ua.NewNumericNodeId(0, id.RootFolder)
	ObjectsFolder        = ua.NewNumericNodeId(0, id.ObjectsFolder)
	TypesFolder          = ua.NewNumericNodeId(0, id.TypesFolder)
	ViewsFolder          = ua.NewNumericNodeId(0, id.ViewsFolder)
	RefOrganizes         = ua.NewNumericNodeId(0, id.Organizes)
	RefHasComponent      = ua.NewNumericNodeId(0, id.HasComponent)
	RefHasProperty       = ua.NewNumericNodeId(0, id.HasProperty)
	RefHasTypeDefinition = ua.NewNumericNodeId(0, id.HasTypeDefinition)
	RefHasSubtype        = ua.NewNumericNodeId(0, id.HasSubtype)
	RefHierarchical      = ua.NewNumericNodeId(0, id.HierarchicalReferences)
	RefReferences        = ua.NewNumericNodeId(0, id.References)
	RefHasEncoding       = ua.NewNumericNodeId(0, id.HasEncoding)
	RefHasModellingRule  = ua.NewNumericNodeId(0, id.HasModellingRule)
	TypeBaseObject       = ua.NewNumericNodeId(0, id.BaseObjectType)
	TypeFolder           = ua.NewNumericNodeId(0, id.FolderType)
	TypeBaseDataVariable = ua.NewNumericNodeId(0, id.BaseDataVariableType)
	TypeProperty         = ua.NewNumericNodeId(0, id.PropertyType)
	DataTypeBaseDataType = ua.NewNumericNodeId(0, id.BaseDataType)
	DataTypeStructure    = ua.NewNumericNodeId(0, id.Structure)
	DataTypeEnumeration  = ua.NewNumericNodeId(0, id.Enumeration)
	DataTypeArgument     = ua.NewNumericNodeId(0, id.Argument)
)

// AccessLevel bits.
const (
	AccessCurrentRead  byte = 0x01
	AccessCurrentWrite byte = 0x02
	AccessHistoryRead  byte = 0x04
	AccessHistoryWrite byte = 0x08
)

// AddFolder adds a folder object organized by parent.
func (a *AddressSpace) AddFolder(parent, nid ua.NodeId, name ua.QualifiedName) (*Node, error) {
	n := &Node{
		ID: nid, Class: ua.NodeClassObject, BrowseName: name, DisplayName: ua.NewLocalizedText(name.Name),
		refs: []Reference{
			{ReferenceType: RefHasTypeDefinition, Target: ua.NewExpandedNodeId(TypeFolder), IsForward: true},
			{ReferenceType: RefOrganizes, Target: ua.NewExpandedNodeId(parent), IsForward: false},
		},
	}
	return n, a.AddNode(n)
}

// AddObject adds an object as a component (or organized child for folders) of parent.
func (a *AddressSpace) AddObject(parent, nid ua.NodeId, name ua.QualifiedName, typeDef ua.NodeId) (*Node, error) {
	if typeDef.IsNull() {
		typeDef = TypeBaseObject
	}
	n := &Node{
		ID: nid, Class: ua.NodeClassObject, BrowseName: name, DisplayName: ua.NewLocalizedText(name.Name),
		refs: []Reference{
			{ReferenceType: RefHasTypeDefinition, Target: ua.NewExpandedNodeId(typeDef), IsForward: true},
			{ReferenceType: a.childRefType(parent), Target: ua.NewExpandedNodeId(parent), IsForward: false},
		},
	}
	return n, a.AddNode(n)
}

func (a *AddressSpace) childRefType(parent ua.NodeId) ua.NodeId {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if p := a.nodes[parent]; p != nil && p.Class == ua.NodeClassObject {
		if td := a.typeDefinitionLocked(p); td.NodeId == TypeFolder || a.isSubtypeLocked(td.NodeId, TypeFolder) {
			return RefOrganizes
		}
	}
	return RefHasComponent
}

// VariableOptions configures AddVariable.
type VariableOptions struct {
	DataType    ua.NodeId // defaults to the data type of the initial value
	ValueRank   int32     // defaults to -1 (scalar) or 1 for array values
	AccessLevel byte      // defaults to CurrentRead
	TypeDef     ua.NodeId // defaults to BaseDataVariableType
	Property    bool      // add with HasProperty / PropertyType
	Description string
}

// AddVariable adds a variable with an initial value as a child of parent.
func (a *AddressSpace) AddVariable(parent, nid ua.NodeId, name ua.QualifiedName, value ua.Variant, opt VariableOptions) (*Node, error) {
	dt := opt.DataType
	if dt.IsNull() {
		dt = builtinDataType(value)
	}
	rank := opt.ValueRank
	if rank == 0 {
		rank = value.ValueRank()
		if value.IsNull() {
			rank = -2
		}
	}
	al := opt.AccessLevel
	if al == 0 {
		al = AccessCurrentRead
	}
	td, rt := opt.TypeDef, a.childRefType(parent)
	if opt.Property {
		td, rt = TypeProperty, RefHasProperty
	} else {
		if rt == RefHasComponent {
			if p := a.Node(parent); p != nil && p.Class == ua.NodeClassVariable {
				rt = RefHasComponent
			}
		}
		if td.IsNull() {
			td = TypeBaseDataVariable
		}
	}
	now := time.Now()
	n := &Node{
		ID: nid, Class: ua.NodeClassVariable, BrowseName: name, DisplayName: ua.NewLocalizedText(name.Name),
		Description: ua.NewLocalizedText(opt.Description),
		DataType:    dt, ValueRank: rank, AccessLevel: al, UserAccessLevel: al,
		value: ua.DataValue{Value: value, SourceTimestamp: now, ServerTimestamp: now},
		refs: []Reference{
			{ReferenceType: RefHasTypeDefinition, Target: ua.NewExpandedNodeId(td), IsForward: true},
			{ReferenceType: rt, Target: ua.NewExpandedNodeId(parent), IsForward: false},
		},
	}
	if value.IsArray() {
		if dims := value.Dimensions(); len(dims) > 0 {
			for _, d := range dims {
				n.ArrayDimensions = append(n.ArrayDimensions, uint32(d))
			}
		} else {
			n.ArrayDimensions = []uint32{0}
		}
	}
	return n, a.AddNode(n)
}

// Argument describes a method argument.
type Argument struct {
	Name        string
	DataType    ua.NodeId
	ValueRank   int32 // 0 means scalar (-1)
	Description string
}

// AddMethod adds a method to an object together with its argument properties.
func (a *AddressSpace) AddMethod(parent, nid ua.NodeId, name ua.QualifiedName, in, out []Argument,
	handler func(ctx ReadContext, objectID ua.NodeId, inputs []ua.Variant) ([]ua.Variant, ua.StatusCode)) (*Node, error) {
	n := &Node{
		ID: nid, Class: ua.NodeClassMethod, BrowseName: name, DisplayName: ua.NewLocalizedText(name.Name),
		Executable: true, OnCall: handler,
		refs: []Reference{{ReferenceType: RefHasComponent, Target: ua.NewExpandedNodeId(parent), IsForward: false}},
	}
	if err := a.AddNode(n); err != nil {
		return nil, err
	}
	addArgs := func(propName string, args []Argument) error {
		if len(args) == 0 {
			return nil
		}
		vals := make([]ua.ExtensionObject, len(args))
		for i, ar := range args {
			rank := ar.ValueRank
			if rank == 0 {
				rank = -1
			}
			var dims []uint32
			if rank > 0 {
				dims = make([]uint32, rank)
			}
			vals[i] = ua.NewExtensionObject(&ua.Argument{
				Name: ar.Name, DataType: ar.DataType, ValueRank: rank, ArrayDimensions: dims,
				Description: ua.NewLocalizedText(ar.Description),
			})
		}
		pid := childID(nid, propName)
		_, err := a.AddVariable(nid, pid, ua.NewQualifiedName(0, propName), ua.NewVariant(vals),
			VariableOptions{DataType: DataTypeArgument, ValueRank: 1, Property: true})
		return err
	}
	if err := addArgs("InputArguments", in); err != nil {
		return nil, err
	}
	if err := addArgs("OutputArguments", out); err != nil {
		return nil, err
	}
	return n, nil
}

// childID derives a child node id from a parent id and a name.
func childID(parent ua.NodeId, name string) ua.NodeId {
	switch parent.Type {
	case ua.IDString:
		return ua.NewStringNodeId(parent.Namespace, parent.Str+"."+name)
	case ua.IDNumeric:
		return ua.NewStringNodeId(parent.Namespace, fmt.Sprintf("%d.%s", parent.Numeric, name))
	}
	return ua.NewStringNodeId(parent.Namespace, parent.String()+"."+name)
}

func builtinDataType(v ua.Variant) ua.NodeId {
	t := v.Type()
	switch t {
	case ua.TypeNull, ua.TypeVariant, ua.TypeDataValue, ua.TypeDiagnosticInfo:
		return DataTypeBaseDataType
	case ua.TypeExtensionObject:
		var eo ua.ExtensionObject
		switch x := v.Value().(type) {
		case ua.ExtensionObject:
			eo = x
		case []ua.ExtensionObject:
			if len(x) > 0 {
				eo = x[0]
			}
		}
		if s, ok := eo.Value.(ua.Structure); ok {
			return s.DataTypeID()
		}
		return DataTypeStructure
	}
	return ua.NewNumericNodeId(0, uint32(t))
}
