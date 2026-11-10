package client

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bamchoh/uaserver/ua"
	"github.com/bamchoh/uaserver/uacp"
	"github.com/bamchoh/uaserver/uasc"
)

// GetEndpoints returns the endpoints of the server at endpointURL. It uses a
// secure channel with the None policy and no session.
func GetEndpoints(ctx context.Context, endpointURL string, limits uacp.ClientLimits) ([]ua.EndpointDescription, error) {
	resp, err := discover[*ua.GetEndpointsResponse](ctx, endpointURL, limits, &ua.GetEndpointsRequest{
		EndpointUrl: endpointURL, ProfileUris: []string{uasc.TransportProfileUaTcp},
	})
	if err != nil {
		return nil, err
	}
	return resp.Endpoints, nil
}

// FindServers returns the servers known to the server (or discovery server)
// at endpointURL.
func FindServers(ctx context.Context, endpointURL string, limits uacp.ClientLimits) ([]ua.ApplicationDescription, error) {
	resp, err := discover[*ua.FindServersResponse](ctx, endpointURL, limits, &ua.FindServersRequest{EndpointUrl: endpointURL})
	if err != nil {
		return nil, err
	}
	return resp.Servers, nil
}

func discover[T ua.Response](ctx context.Context, endpointURL string, limits uacp.ClientLimits, req ua.Request) (T, error) {
	var zero T
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	conn, err := uacp.Dial(ctx, endpointURL, limits)
	if err != nil {
		return zero, fmt.Errorf("client: %w", err)
	}
	ch, err := uasc.OpenClientChannel(ctx, conn, uasc.ClientConfig{SecurityPolicyURI: uasc.SecurityPolicyNone})
	if err != nil {
		return zero, fmt.Errorf("client: %w", err)
	}
	defer ch.Close()
	h := req.Header()
	h.Timestamp = time.Now()
	h.RequestHandle = 1
	if d, ok := ctx.Deadline(); ok {
		h.TimeoutHint = uint32(max(time.Until(d), time.Millisecond) / time.Millisecond)
	}
	msg, err := ch.Send(ctx, req)
	if err != nil {
		return zero, fmt.Errorf("client: %s: %w", serviceName(req), err)
	}
	if f, ok := msg.(*ua.ServiceFault); ok {
		return zero, fmt.Errorf("client: %s: %w", serviceName(req), f.ResponseHeader.ServiceResult)
	}
	r, ok := msg.(T)
	if !ok {
		return zero, fmt.Errorf("client: %s: unexpected response %T", serviceName(req), msg)
	}
	if st := r.Header().ServiceResult; st.IsBad() {
		return zero, fmt.Errorf("client: %s: %w", serviceName(req), st)
	}
	return r, nil
}

// SelectEndpoint returns the endpoint with the security policy and mode. An
// empty policy selects the most secure endpoint supported by this client
// (mode is then ignored).
func SelectEndpoint(eps []ua.EndpointDescription, policyURI string, mode ua.MessageSecurityMode) (ua.EndpointDescription, error) {
	var usable []ua.EndpointDescription
	for _, ep := range eps {
		if uasc.PolicyByURI(ep.SecurityPolicyUri) == nil {
			continue
		}
		if ep.TransportProfileUri != "" && ep.TransportProfileUri != uasc.TransportProfileUaTcp {
			continue
		}
		usable = append(usable, ep)
	}
	if policyURI == "" {
		if len(usable) == 0 {
			return ua.EndpointDescription{}, fmt.Errorf("client: the server has no endpoint this client supports")
		}
		sort.SliceStable(usable, func(i, j int) bool { return usable[i].SecurityLevel > usable[j].SecurityLevel })
		return usable[0], nil
	}
	if mode == ua.MessageSecurityModeInvalid {
		mode = ua.MessageSecurityModeSignAndEncrypt
		if policyURI == uasc.SecurityPolicyNone {
			mode = ua.MessageSecurityModeNone
		}
	}
	for _, ep := range usable {
		if ep.SecurityPolicyUri == policyURI && ep.SecurityMode == mode {
			return ep, nil
		}
	}
	var have []string
	for _, ep := range eps {
		name := ep.SecurityPolicyUri
		if p := uasc.PolicyByURI(name); p != nil {
			name = p.Name
		}
		have = append(have, name+"/"+ep.SecurityMode.String())
	}
	want := policyURI
	if p := uasc.PolicyByURI(policyURI); p != nil {
		want = p.Name
	}
	return ua.EndpointDescription{}, fmt.Errorf("client: the server has no %s/%s endpoint (available: %s)",
		want, mode, strings.Join(have, ", "))
}
