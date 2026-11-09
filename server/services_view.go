package server

import (
	"encoding/binary"

	"github.com/bamchoh/uaserver/ua"
	"github.com/bamchoh/uaserver/ua/id"
)

type browseCP struct {
	refs []ua.ReferenceDescription
	max  int
}

func (s *Server) browse(sess *Session, r *ua.BrowseRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.NodesToBrowse)); st != 0 {
		return fault(hdr, st)
	}
	if !r.View.ViewId.IsNull() {
		v := s.as.Node(r.View.ViewId)
		if v == nil || v.Class != ua.NodeClassView {
			return fault(hdr, ua.StatusBadViewIdUnknown)
		}
	}
	results := make([]ua.BrowseResult, len(r.NodesToBrowse))
	for i, bd := range r.NodesToBrowse {
		refs, st := s.browseNode(bd)
		if st != 0 {
			results[i] = ua.BrowseResult{StatusCode: st}
			continue
		}
		results[i] = sess.paginate(refs, int(r.RequestedMaxReferencesPerNode))
	}
	return &ua.BrowseResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func (sess *Session) paginate(refs []ua.ReferenceDescription, max int) ua.BrowseResult {
	if refs == nil {
		refs = []ua.ReferenceDescription{}
	}
	if max <= 0 || len(refs) <= max {
		return ua.BrowseResult{References: refs}
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(sess.browseCPs) >= sess.srv.cfg.MaxContinuationPts {
		return ua.BrowseResult{StatusCode: ua.StatusBadNoContinuationPoints}
	}
	sess.cpCounter++
	cp := make([]byte, 8)
	binary.LittleEndian.PutUint64(cp, sess.cpCounter)
	sess.browseCPs[string(cp)] = &browseCP{refs: refs[max:], max: max}
	return ua.BrowseResult{References: refs[:max], ContinuationPoint: cp}
}

func (s *Server) browseNext(sess *Session, r *ua.BrowseNextRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.ContinuationPoints)); st != 0 {
		return fault(hdr, st)
	}
	results := make([]ua.BrowseResult, len(r.ContinuationPoints))
	for i, cp := range r.ContinuationPoints {
		sess.mu.Lock()
		c := sess.browseCPs[string(cp)]
		delete(sess.browseCPs, string(cp))
		sess.mu.Unlock()
		if c == nil {
			results[i] = ua.BrowseResult{StatusCode: ua.StatusBadContinuationPointInvalid}
			continue
		}
		if r.ReleaseContinuationPoints {
			results[i] = ua.BrowseResult{}
			continue
		}
		results[i] = sess.paginate(c.refs, c.max)
	}
	return &ua.BrowseNextResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func (s *Server) browseNode(bd ua.BrowseDescription) ([]ua.ReferenceDescription, ua.StatusCode) {
	n := s.as.Node(bd.NodeId)
	if n == nil {
		return nil, ua.StatusBadNodeIdUnknown
	}
	if bd.BrowseDirection < ua.BrowseDirectionForward || bd.BrowseDirection > ua.BrowseDirectionBoth {
		return nil, ua.StatusBadBrowseDirectionInvalid
	}
	if !bd.ReferenceTypeId.IsNull() {
		rt := s.as.Node(bd.ReferenceTypeId)
		if rt == nil || rt.Class != ua.NodeClassReferenceType {
			return nil, ua.StatusBadReferenceTypeIdInvalid
		}
	}
	var out []ua.ReferenceDescription
	s.as.mu.RLock()
	defer s.as.mu.RUnlock()
	for _, ref := range n.refs {
		if bd.BrowseDirection == ua.BrowseDirectionForward && !ref.IsForward ||
			bd.BrowseDirection == ua.BrowseDirectionInverse && ref.IsForward {
			continue
		}
		if !bd.ReferenceTypeId.IsNull() {
			if bd.IncludeSubtypes {
				if !s.as.isSubtypeLocked(ref.ReferenceType, bd.ReferenceTypeId) {
					continue
				}
			} else if ref.ReferenceType != bd.ReferenceTypeId {
				continue
			}
		}
		var target *Node
		if ref.Target.IsLocal() && ref.Target.NamespaceURI == "" {
			target = s.as.nodes[ref.Target.NodeId]
		}
		if bd.NodeClassMask != 0 {
			if target == nil || uint32(target.Class)&bd.NodeClassMask == 0 {
				continue
			}
		}
		rd := ua.ReferenceDescription{NodeId: ref.Target}
		m := bd.ResultMask
		if m&uint32(ua.BrowseResultMaskReferenceTypeId) != 0 {
			rd.ReferenceTypeId = ref.ReferenceType
		}
		if m&uint32(ua.BrowseResultMaskIsForward) != 0 {
			rd.IsForward = ref.IsForward
		}
		if target != nil {
			if m&uint32(ua.BrowseResultMaskNodeClass) != 0 {
				rd.NodeClass = target.Class
			}
			if m&uint32(ua.BrowseResultMaskBrowseName) != 0 {
				rd.BrowseName = target.BrowseName
			}
			if m&uint32(ua.BrowseResultMaskDisplayName) != 0 {
				rd.DisplayName = target.DisplayName
			}
			if m&uint32(ua.BrowseResultMaskTypeDefinition) != 0 &&
				(target.Class == ua.NodeClassObject || target.Class == ua.NodeClassVariable) {
				rd.TypeDefinition = s.as.typeDefinitionLocked(target)
			}
		}
		out = append(out, rd)
	}
	return out, 0
}

func (s *Server) translateBrowsePaths(sess *Session, r *ua.TranslateBrowsePathsToNodeIdsRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.BrowsePaths)); st != 0 {
		return fault(hdr, st)
	}
	results := make([]ua.BrowsePathResult, len(r.BrowsePaths))
	for i, bp := range r.BrowsePaths {
		results[i] = s.translatePath(bp)
	}
	return &ua.TranslateBrowsePathsToNodeIdsResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func (s *Server) translatePath(bp ua.BrowsePath) ua.BrowsePathResult {
	if s.as.Node(bp.StartingNode) == nil {
		return ua.BrowsePathResult{StatusCode: ua.StatusBadNodeIdUnknown}
	}
	if len(bp.RelativePath.Elements) == 0 {
		return ua.BrowsePathResult{StatusCode: ua.StatusBadNothingToDo}
	}
	for _, el := range bp.RelativePath.Elements {
		if el.TargetName.Name == "" {
			return ua.BrowsePathResult{StatusCode: ua.StatusBadBrowseNameInvalid}
		}
	}
	current := []ua.NodeId{bp.StartingNode}
	s.as.mu.RLock()
	defer s.as.mu.RUnlock()
	for _, el := range bp.RelativePath.Elements {
		var next []ua.NodeId
		seen := map[ua.NodeId]bool{}
		for _, nid := range current {
			n := s.as.nodes[nid]
			if n == nil {
				continue
			}
			for _, ref := range n.refs {
				if ref.IsForward == el.IsInverse {
					continue
				}
				if !el.ReferenceTypeId.IsNull() {
					if el.IncludeSubtypes {
						if !s.as.isSubtypeLocked(ref.ReferenceType, el.ReferenceTypeId) {
							continue
						}
					} else if ref.ReferenceType != el.ReferenceTypeId {
						continue
					}
				}
				t := s.as.nodes[ref.Target.NodeId]
				if t == nil || !ref.Target.IsLocal() || t.BrowseName != el.TargetName || seen[t.ID] {
					continue
				}
				seen[t.ID] = true
				next = append(next, t.ID)
			}
		}
		if len(next) == 0 {
			return ua.BrowsePathResult{StatusCode: ua.StatusBadNoMatch}
		}
		current = next
	}
	targets := make([]ua.BrowsePathTarget, len(current))
	for i, nid := range current {
		targets[i] = ua.BrowsePathTarget{TargetId: ua.NewExpandedNodeId(nid), RemainingPathIndex: 0xFFFFFFFF}
	}
	return ua.BrowsePathResult{Targets: targets}
}

func (s *Server) registerNodes(r *ua.RegisterNodesRequest) ua.Structure {
	if st := s.checkOperations(len(r.NodesToRegister)); st != 0 {
		return fault(&r.RequestHeader, st)
	}
	return &ua.RegisterNodesResponse{ResponseHeader: respHeader(&r.RequestHeader, 0), RegisteredNodeIds: r.NodesToRegister}
}

func (s *Server) unregisterNodes(r *ua.UnregisterNodesRequest) ua.Structure {
	if st := s.checkOperations(len(r.NodesToUnregister)); st != 0 {
		return fault(&r.RequestHeader, st)
	}
	return &ua.UnregisterNodesResponse{ResponseHeader: respHeader(&r.RequestHeader, 0)}
}

// --- Method service set ---

func (s *Server) call(sess *Session, r *ua.CallRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.MethodsToCall)); st != 0 {
		return fault(hdr, st)
	}
	results := make([]ua.CallMethodResult, len(r.MethodsToCall))
	for i, m := range r.MethodsToCall {
		results[i] = s.callMethod(ReadContext{Session: sess}, m)
	}
	return &ua.CallResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func (s *Server) methodArguments(method ua.NodeId, name string) []ua.Argument {
	m := s.as.Node(method)
	if m == nil {
		return nil
	}
	for _, ref := range m.References() {
		if !ref.IsForward || ref.ReferenceType != RefHasProperty {
			continue
		}
		p := s.as.Node(ref.Target.NodeId)
		if p == nil || p.BrowseName.Name != name {
			continue
		}
		dv := s.as.readValue(p, ReadContext{})
		eos, _ := dv.Value.Value().([]ua.ExtensionObject)
		var args []ua.Argument
		for _, eo := range eos {
			if a, ok := eo.Value.(*ua.Argument); ok {
				args = append(args, *a)
			}
		}
		return args
	}
	return nil
}

func (s *Server) objectHasMethod(obj, method ua.NodeId) bool {
	o := s.as.Node(obj)
	if o == nil {
		return false
	}
	for _, ref := range o.References() {
		if ref.IsForward && ref.Target.NodeId == method && s.as.IsSubtype(ref.ReferenceType, RefHasComponent) {
			return true
		}
	}
	// Methods defined on the type are callable on instances.
	s.as.mu.RLock()
	td := s.as.typeDefinitionLocked(o)
	s.as.mu.RUnlock()
	for t := td.NodeId; !t.IsNull(); {
		tn := s.as.Node(t)
		if tn == nil {
			break
		}
		for _, ref := range tn.References() {
			if ref.IsForward && ref.Target.NodeId == method {
				return true
			}
		}
		sup, ok := s.as.SuperType(t)
		if !ok {
			break
		}
		t = sup
	}
	return false
}

func (s *Server) callMethod(ctx ReadContext, m ua.CallMethodRequest) ua.CallMethodResult {
	obj := s.as.Node(m.ObjectId)
	if obj == nil {
		return ua.CallMethodResult{StatusCode: ua.StatusBadNodeIdUnknown}
	}
	method := s.as.Node(m.MethodId)
	if method == nil || method.Class != ua.NodeClassMethod {
		return ua.CallMethodResult{StatusCode: ua.StatusBadMethodInvalid}
	}
	if obj.Class != ua.NodeClassObject && obj.Class != ua.NodeClassObjectType {
		return ua.CallMethodResult{StatusCode: ua.StatusBadNodeIdInvalid}
	}
	if !s.objectHasMethod(m.ObjectId, m.MethodId) {
		return ua.CallMethodResult{StatusCode: ua.StatusBadMethodInvalid}
	}
	if !method.Executable {
		return ua.CallMethodResult{StatusCode: ua.StatusBadNotExecutable}
	}
	args := s.methodArguments(m.MethodId, "InputArguments")
	if len(m.InputArguments) < len(args) {
		return ua.CallMethodResult{StatusCode: ua.StatusBadArgumentsMissing}
	}
	if len(m.InputArguments) > len(args) {
		return ua.CallMethodResult{StatusCode: ua.StatusBadTooManyArguments}
	}
	argResults := make([]ua.StatusCode, len(args))
	bad := false
	for i, a := range args {
		tmp := &Node{DataType: a.DataType, ValueRank: a.ValueRank}
		if st := s.checkValueType(tmp, m.InputArguments[i]); st != 0 {
			argResults[i] = ua.StatusBadTypeMismatch
			bad = true
		}
	}
	if bad {
		return ua.CallMethodResult{StatusCode: ua.StatusBadInvalidArgument, InputArgumentResults: argResults}
	}
	handler := method.OnCall
	if handler == nil {
		handler = s.builtinMethod(m.MethodId)
	}
	if handler == nil {
		return ua.CallMethodResult{StatusCode: ua.StatusBadNotImplemented}
	}
	out, st := handler(ctx, m.ObjectId, m.InputArguments)
	if out == nil {
		out = []ua.Variant{}
	}
	return ua.CallMethodResult{StatusCode: st, OutputArguments: out}
}

// builtinMethod implements standard methods of the Server object.
func (s *Server) builtinMethod(mid ua.NodeId) func(ReadContext, ua.NodeId, []ua.Variant) ([]ua.Variant, ua.StatusCode) {
	if mid == ua.NewNumericNodeId(0, id.Server_GetMonitoredItems) {
		return func(ctx ReadContext, _ ua.NodeId, in []ua.Variant) ([]ua.Variant, ua.StatusCode) {
			subID, ok := in[0].Value().(uint32)
			if !ok || ctx.Session == nil {
				return nil, ua.StatusBadInvalidArgument
			}
			ctx.Session.mu.Lock()
			sub := ctx.Session.subs[subID]
			ctx.Session.mu.Unlock()
			if sub == nil {
				return nil, ua.StatusBadSubscriptionIdInvalid
			}
			server, client := sub.itemHandles()
			return []ua.Variant{ua.NewVariant(server), ua.NewVariant(client)}, 0
		}
	}
	return nil
}
