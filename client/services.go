package client

import (
	"context"
	"fmt"

	"github.com/bamchoh/uastack/ua"
	uaid "github.com/bamchoh/uastack/ua/id"
)

// --- Attribute service set ---

// Read calls the Read service.
func (c *Client) Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error) {
	return call[*ua.ReadResponse](ctx, c, req)
}

// Write calls the Write service.
func (c *Client) Write(ctx context.Context, req *ua.WriteRequest) (*ua.WriteResponse, error) {
	return call[*ua.WriteResponse](ctx, c, req)
}

// ReadValue reads the Value attribute of a node. If the value has a bad
// status, the DataValue is returned together with the status as error.
func (c *Client) ReadValue(ctx context.Context, nodeID ua.NodeId) (ua.DataValue, error) {
	vs, err := c.ReadValues(ctx, nodeID)
	if err != nil {
		return ua.DataValue{}, err
	}
	if vs[0].Status.IsBad() {
		return vs[0], fmt.Errorf("client: read %s: %w", nodeID, vs[0].Status)
	}
	return vs[0], nil
}

// ReadValues reads the Value attribute of several nodes in one request. The
// status of each value is in its DataValue.
func (c *Client) ReadValues(ctx context.Context, nodeIDs ...ua.NodeId) ([]ua.DataValue, error) {
	req := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnBoth}
	for _, id := range nodeIDs {
		req.NodesToRead = append(req.NodesToRead, ua.ReadValueId{NodeId: id, AttributeId: ua.AttributeIdValue})
	}
	return c.readAll(ctx, req)
}

// ReadAttributes reads attributes of one node.
func (c *Client) ReadAttributes(ctx context.Context, nodeID ua.NodeId, attributeIDs ...uint32) ([]ua.DataValue, error) {
	req := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	for _, a := range attributeIDs {
		req.NodesToRead = append(req.NodesToRead, ua.ReadValueId{NodeId: nodeID, AttributeId: a})
	}
	return c.readAll(ctx, req)
}

func (c *Client) readAll(ctx context.Context, req *ua.ReadRequest) ([]ua.DataValue, error) {
	resp, err := c.Read(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != len(req.NodesToRead) {
		return nil, fmt.Errorf("client: Read returned %d results for %d nodes", len(resp.Results), len(req.NodesToRead))
	}
	return resp.Results, nil
}

// WriteValue writes the Value attribute of a node.
func (c *Client) WriteValue(ctx context.Context, nodeID ua.NodeId, v ua.Variant) error {
	resp, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []ua.WriteValue{
		{NodeId: nodeID, AttributeId: ua.AttributeIdValue, Value: ua.NewDataValue(v)},
	}})
	if err != nil {
		return err
	}
	if len(resp.Results) != 1 {
		return fmt.Errorf("client: Write returned %d results for 1 node", len(resp.Results))
	}
	if st := resp.Results[0]; st.IsBad() {
		return fmt.Errorf("client: write %s: %w", nodeID, st)
	}
	return nil
}

// --- View service set ---

// Browse calls the Browse service.
func (c *Client) Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	return call[*ua.BrowseResponse](ctx, c, req)
}

// BrowseNext calls the BrowseNext service.
func (c *Client) BrowseNext(ctx context.Context, req *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error) {
	return call[*ua.BrowseNextResponse](ctx, c, req)
}

// BrowseAll browses one node and follows continuation points until all
// references are returned.
func (c *Client) BrowseAll(ctx context.Context, desc ua.BrowseDescription) ([]ua.ReferenceDescription, error) {
	resp, err := c.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []ua.BrowseDescription{desc}})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != 1 {
		return nil, fmt.Errorf("client: Browse returned %d results for 1 node", len(resp.Results))
	}
	r := resp.Results[0]
	refs := r.References
	for {
		if r.StatusCode.IsBad() {
			return refs, fmt.Errorf("client: browse %s: %w", desc.NodeId, r.StatusCode)
		}
		if len(r.ContinuationPoint) == 0 {
			return refs, nil
		}
		next, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{ContinuationPoints: [][]byte{r.ContinuationPoint}})
		if err != nil {
			return refs, err
		}
		if len(next.Results) != 1 {
			return refs, fmt.Errorf("client: BrowseNext returned %d results for 1 continuation point", len(next.Results))
		}
		r = next.Results[0]
		refs = append(refs, r.References...)
	}
}

// BrowseChildren returns the nodes referenced by a node with forward
// hierarchical references (all result fields).
func (c *Client) BrowseChildren(ctx context.Context, nodeID ua.NodeId) ([]ua.ReferenceDescription, error) {
	return c.BrowseAll(ctx, ua.BrowseDescription{
		NodeId:          nodeID,
		BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeId: ua.NewNumericNodeId(0, uaid.HierarchicalReferences),
		IncludeSubtypes: true,
		ResultMask:      uint32(ua.BrowseResultMaskAll),
	})
}

// TranslateBrowsePathsToNodeIds calls the TranslateBrowsePathsToNodeIds service.
func (c *Client) TranslateBrowsePathsToNodeIds(ctx context.Context, req *ua.TranslateBrowsePathsToNodeIdsRequest) (*ua.TranslateBrowsePathsToNodeIdsResponse, error) {
	return call[*ua.TranslateBrowsePathsToNodeIdsResponse](ctx, c, req)
}

// TranslatePath resolves a path of browse names, following hierarchical
// references from start, to a NodeId.
func (c *Client) TranslatePath(ctx context.Context, start ua.NodeId, path ...ua.QualifiedName) (ua.NodeId, error) {
	bp := ua.BrowsePath{StartingNode: start}
	for _, name := range path {
		bp.RelativePath.Elements = append(bp.RelativePath.Elements, ua.RelativePathElement{
			ReferenceTypeId: ua.NewNumericNodeId(0, uaid.HierarchicalReferences),
			IncludeSubtypes: true,
			TargetName:      name,
		})
	}
	resp, err := c.TranslateBrowsePathsToNodeIds(ctx, &ua.TranslateBrowsePathsToNodeIdsRequest{BrowsePaths: []ua.BrowsePath{bp}})
	if err != nil {
		return ua.NodeId{}, err
	}
	if len(resp.Results) != 1 {
		return ua.NodeId{}, fmt.Errorf("client: TranslateBrowsePathsToNodeIds returned %d results for 1 path", len(resp.Results))
	}
	r := resp.Results[0]
	if r.StatusCode.IsBad() {
		return ua.NodeId{}, fmt.Errorf("client: translate path: %w", r.StatusCode)
	}
	for _, t := range r.Targets {
		if t.TargetId.IsLocal() && t.TargetId.NamespaceURI == "" {
			return t.TargetId.NodeId, nil
		}
	}
	return ua.NodeId{}, fmt.Errorf("client: translate path: no local target: %w", ua.StatusBadNoMatch)
}

// RegisterNodes calls the RegisterNodes service.
func (c *Client) RegisterNodes(ctx context.Context, nodeIDs ...ua.NodeId) ([]ua.NodeId, error) {
	resp, err := call[*ua.RegisterNodesResponse](ctx, c, &ua.RegisterNodesRequest{NodesToRegister: nodeIDs})
	if err != nil {
		return nil, err
	}
	return resp.RegisteredNodeIds, nil
}

// UnregisterNodes calls the UnregisterNodes service.
func (c *Client) UnregisterNodes(ctx context.Context, nodeIDs ...ua.NodeId) error {
	_, err := call[*ua.UnregisterNodesResponse](ctx, c, &ua.UnregisterNodesRequest{NodesToUnregister: nodeIDs})
	return err
}

// --- Method service set ---

// Call calls the Call service.
func (c *Client) Call(ctx context.Context, req *ua.CallRequest) (*ua.CallResponse, error) {
	return call[*ua.CallResponse](ctx, c, req)
}

// CallMethod calls one method and returns its output arguments.
func (c *Client) CallMethod(ctx context.Context, objectID, methodID ua.NodeId, args ...ua.Variant) ([]ua.Variant, error) {
	resp, err := c.Call(ctx, &ua.CallRequest{MethodsToCall: []ua.CallMethodRequest{
		{ObjectId: objectID, MethodId: methodID, InputArguments: args},
	}})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != 1 {
		return nil, fmt.Errorf("client: Call returned %d results for 1 method", len(resp.Results))
	}
	r := resp.Results[0]
	if r.StatusCode.IsBad() {
		for i, st := range r.InputArgumentResults {
			if st.IsBad() {
				return nil, fmt.Errorf("client: call %s: input argument %d: %w", methodID, i, st)
			}
		}
		return nil, fmt.Errorf("client: call %s: %w", methodID, r.StatusCode)
	}
	return r.OutputArguments, nil
}

// --- helpers ---

// NamespaceArray reads the server's namespace table.
func (c *Client) NamespaceArray(ctx context.Context) ([]string, error) {
	dv, err := c.ReadValue(ctx, ua.NewNumericNodeId(0, uaid.Server_NamespaceArray))
	if err != nil {
		return nil, err
	}
	ns, ok := dv.Value.Value().([]string)
	if !ok {
		return nil, fmt.Errorf("client: NamespaceArray has the unexpected type %s", dv.Value.Type())
	}
	return ns, nil
}

// NamespaceIndex returns the index of a namespace URI in the server's namespace table.
func (c *Client) NamespaceIndex(ctx context.Context, uri string) (uint16, error) {
	ns, err := c.NamespaceArray(ctx)
	if err != nil {
		return 0, err
	}
	for i, u := range ns {
		if u == uri {
			return uint16(i), nil
		}
	}
	return 0, fmt.Errorf("client: namespace %q not found", uri)
}
