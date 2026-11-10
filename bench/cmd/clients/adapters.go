package main

import (
	"context"
	"fmt"
	"time"

	"github.com/bamchoh/uastack/bench/internal/memstat"
	"github.com/bamchoh/uastack/client"
	ua "github.com/bamchoh/uastack/ua"
	uaid "github.com/bamchoh/uastack/ua/id"
	"github.com/bamchoh/uastack/uasc"
	"github.com/gopcua/opcua"
	gid "github.com/gopcua/opcua/id"
	gua "github.com/gopcua/opcua/ua"
)

// --- uastack client ---

type uastackClient struct {
	c   *client.Client
	e   *env
	ids []ua.NodeId
}

func dialUAStack(ctx context.Context, e *env, secure bool) (benchClient, error) {
	cfg := client.Config{
		ApplicationURI: "urn:bench:client", RequestTimeout: 30 * time.Second, KeepAliveInterval: -1,
	}
	if secure {
		cfg.SecurityPolicy = uasc.SecurityPolicyBasic256Sha256
		cfg.SecurityMode = ua.MessageSecurityModeSignAndEncrypt
		cfg.Certificate, cfg.PrivateKey = e.certDER, e.key
		cfg.AutoAcceptUntrustedCertificates = true
	}
	c, err := client.Dial(ctx, e.endpoint, cfg)
	if err != nil {
		return nil, err
	}
	ids := make([]ua.NodeId, memstat.NumVars)
	for i := range ids {
		ids[i] = ua.NewStringNodeId(e.ns, e.varName(i))
	}
	return &uastackClient{c: c, e: e, ids: ids}, nil
}

func (u *uastackClient) read(ctx context.Context, n int) error {
	vs, err := u.c.ReadValues(ctx, u.ids[:n]...)
	if err != nil {
		return err
	}
	for _, v := range vs {
		if v.Status.IsBad() {
			return v.Status
		}
	}
	return nil
}

func (u *uastackClient) write(ctx context.Context, i int, v int32) error {
	return u.c.WriteValue(ctx, u.ids[i], ua.NewVariant(v))
}

func (u *uastackClient) browse(ctx context.Context) (int, error) {
	refs, err := u.c.BrowseAll(ctx, ua.BrowseDescription{
		NodeId: ua.NewNumericNodeId(u.e.ns, memstat.FolderID), BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeId: ua.NewNumericNodeId(0, uaid.HierarchicalReferences), IncludeSubtypes: true,
		ResultMask: uint32(ua.BrowseResultMaskAll),
	})
	return len(refs), err
}

func (u *uastackClient) subscribe(ctx context.Context, i int) (func(int32) error, func(), error) {
	sub, err := u.c.CreateSubscription(ctx, client.SubscriptionParams{PublishingInterval: 10 * time.Millisecond})
	if err != nil {
		return nil, nil, err
	}
	if _, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, ua.MonitoredItemCreateRequest{
		ItemToMonitor:       ua.ReadValueId{NodeId: u.ids[i], AttributeId: ua.AttributeIdValue},
		MonitoringMode:      ua.MonitoringModeReporting,
		RequestedParameters: ua.MonitoringParameters{ClientHandle: 42, SamplingInterval: 0, QueueSize: 10, DiscardOldest: true},
	}); err != nil {
		return nil, nil, err
	}
	wait := func(want int32) error {
		timeout := time.After(5 * time.Second)
		for {
			select {
			case n, ok := <-sub.Notifications():
				if !ok {
					return fmt.Errorf("subscription closed")
				}
				for _, dc := range n.DataChanges {
					if v, ok := dc.Value.Value.Value().(int32); ok && (want == -1 || v == want) {
						return nil
					}
				}
			case <-timeout:
				return fmt.Errorf("no notification for value %d", want)
			}
		}
	}
	return wait, func() { _ = sub.Delete(context.Background()) }, nil
}

func (u *uastackClient) close(ctx context.Context) { _ = u.c.Close(ctx) }

// --- gopcua client ---

type gopcuaClient struct {
	c   *opcua.Client
	e   *env
	ids []*gua.NodeID
}

func dialGopcua(ctx context.Context, e *env, secure bool) (benchClient, error) {
	opts := []opcua.Option{opcua.AutoReconnect(false), opcua.RequestTimeout(30 * time.Second)}
	if secure {
		eps, err := opcua.GetEndpoints(ctx, e.endpoint)
		if err != nil {
			return nil, err
		}
		ep, err := opcua.SelectEndpoint(eps, gua.SecurityPolicyURIBasic256Sha256, gua.MessageSecurityModeSignAndEncrypt)
		if err != nil {
			return nil, err
		}
		opts = append(opts,
			opcua.SecurityFromEndpoint(ep, gua.UserTokenTypeAnonymous),
			opcua.Certificate(e.certDER), opcua.PrivateKey(e.key),
			opcua.ApplicationURI("urn:bench:client"))
	} else {
		opts = append(opts, opcua.SecurityMode(gua.MessageSecurityModeNone), opcua.SecurityPolicy("None"), opcua.AuthAnonymous())
	}
	c, err := opcua.NewClient(e.endpoint, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	ids := make([]*gua.NodeID, memstat.NumVars)
	for i := range ids {
		ids[i] = gua.NewStringNodeID(e.ns, e.varName(i))
	}
	return &gopcuaClient{c: c, e: e, ids: ids}, nil
}

func (g *gopcuaClient) read(ctx context.Context, n int) error {
	req := &gua.ReadRequest{TimestampsToReturn: gua.TimestampsToReturnBoth}
	for _, id := range g.ids[:n] {
		req.NodesToRead = append(req.NodesToRead, &gua.ReadValueID{NodeID: id, AttributeID: gua.AttributeIDValue})
	}
	resp, err := g.c.Read(ctx, req)
	if err != nil {
		return err
	}
	if len(resp.Results) != n {
		return fmt.Errorf("read returned %d results", len(resp.Results))
	}
	for _, r := range resp.Results {
		if r.Status != gua.StatusOK {
			return r.Status
		}
	}
	return nil
}

func (g *gopcuaClient) write(ctx context.Context, i int, v int32) error {
	resp, err := g.c.Write(ctx, &gua.WriteRequest{NodesToWrite: []*gua.WriteValue{{
		NodeID: g.ids[i], AttributeID: gua.AttributeIDValue,
		Value: &gua.DataValue{EncodingMask: gua.DataValueValue, Value: gua.MustVariant(v)},
	}}})
	if err != nil {
		return err
	}
	if resp.Results[0] != gua.StatusOK {
		return resp.Results[0]
	}
	return nil
}

func (g *gopcuaClient) browse(ctx context.Context) (int, error) {
	resp, err := g.c.Browse(ctx, &gua.BrowseRequest{NodesToBrowse: []*gua.BrowseDescription{{
		NodeID: gua.NewNumericNodeID(g.e.ns, memstat.FolderID), BrowseDirection: gua.BrowseDirectionForward,
		ReferenceTypeID: gua.NewNumericNodeID(0, gid.HierarchicalReferences), IncludeSubtypes: true,
		ResultMask: uint32(gua.BrowseResultMaskAll),
	}}})
	if err != nil {
		return 0, err
	}
	r := resp.Results[0]
	count := len(r.References)
	for len(r.ContinuationPoint) > 0 {
		next, err := g.c.BrowseNext(ctx, &gua.BrowseNextRequest{ContinuationPoints: [][]byte{r.ContinuationPoint}})
		if err != nil {
			return count, err
		}
		r = next.Results[0]
		count += len(r.References)
	}
	return count, nil
}

func (g *gopcuaClient) subscribe(ctx context.Context, i int) (func(int32) error, func(), error) {
	notify := make(chan *opcua.PublishNotificationData, 64)
	sub, err := g.c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 10 * time.Millisecond}, notify)
	if err != nil {
		return nil, nil, err
	}
	mi := opcua.NewMonitoredItemCreateRequestWithDefaults(g.ids[i], gua.AttributeIDValue, 42)
	if _, err := sub.Monitor(ctx, gua.TimestampsToReturnBoth, mi); err != nil {
		return nil, nil, err
	}
	wait := func(want int32) error {
		timeout := time.After(5 * time.Second)
		for {
			select {
			case nd := <-notify:
				if nd.Error != nil {
					return nd.Error
				}
				if dcn, ok := nd.Value.(*gua.DataChangeNotification); ok {
					for _, it := range dcn.MonitoredItems {
						if v, ok := it.Value.Value.Value().(int32); ok && (want == -1 || v == want) {
							return nil
						}
					}
				}
			case <-timeout:
				return fmt.Errorf("no notification for value %d", want)
			}
		}
	}
	return wait, func() { _ = sub.Cancel(context.Background()) }, nil
}

func (g *gopcuaClient) close(ctx context.Context) { _ = g.c.Close(ctx) }
