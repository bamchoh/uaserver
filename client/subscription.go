package client

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bamchoh/uaserver/ua"
)

// SubscriptionParams are the requested subscription settings. The server
// may revise them.
type SubscriptionParams struct {
	// PublishingInterval defaults to 1 second.
	PublishingInterval time.Duration
	// KeepAliveCount is the number of publishing intervals without
	// notifications after which the server sends a keep-alive (default 10).
	KeepAliveCount uint32
	// LifetimeCount is the number of publishing intervals without Publish
	// requests after which the server deletes the subscription (default
	// 10 times KeepAliveCount).
	LifetimeCount              uint32
	MaxNotificationsPerPublish uint32
	Priority                   byte
	// Disabled creates the subscription with publishing disabled.
	Disabled bool
	// BufferSize is the capacity of the Notifications channel (default 256).
	// When the channel is full, receiving further notifications waits until
	// the application reads from it.
	BufferSize int
}

// Notification is one notification message of a subscription.
type Notification struct {
	SubscriptionID uint32
	SequenceNumber uint32
	PublishTime    time.Time
	DataChanges    []ua.MonitoredItemNotification
	Events         []ua.EventFieldList
	// StatusChange is set when the server reported a change of the
	// subscription status (e.g. BadTimeout when the subscription expired).
	StatusChange ua.StatusCode
	// Err is set on the last notification when the subscription ends
	// because the client was closed or the connection was lost.
	Err error
}

// MonitoredItem is a created monitored item.
type MonitoredItem struct {
	ID           uint32
	ClientHandle uint32
	NodeID       ua.NodeId
	AttributeID  uint32
	// SamplingInterval and QueueSize are the values revised by the server.
	SamplingInterval time.Duration
	QueueSize        uint32
	Status           ua.StatusCode
}

// Subscription is a subscription of the client's session.
type Subscription struct {
	c  *Client
	id atomic.Uint32 // changes when the subscription is recreated after a reconnect

	params SubscriptionParams // as requested, to recreate the subscription

	notify     chan Notification
	done       chan struct{}
	closeOnce  sync.Once
	nextHandle atomic.Uint32

	deliverMu      sync.Mutex // serializes delivery, held while waiting on notify
	mu             sync.Mutex
	interval       time.Duration
	keepAliveCount uint32
	lifetimeCount  uint32
	enabled        bool
	items          map[uint32]*itemDef               // by client handle
	nextSeq        uint32                            // next sequence number to deliver
	held           map[uint32]ua.NotificationMessage // received ahead of nextSeq
}

// itemDef is a created monitored item, kept to recreate it.
type itemDef struct {
	id  uint32
	ts  ua.TimestampsToReturn
	req ua.MonitoredItemCreateRequest
}

// CreateSubscription creates a subscription. Notifications are received
// from Subscription.Notifications.
func (c *Client) CreateSubscription(ctx context.Context, p SubscriptionParams) (*Subscription, error) {
	if p.PublishingInterval <= 0 {
		p.PublishingInterval = time.Second
	}
	if p.KeepAliveCount == 0 {
		p.KeepAliveCount = 10
	}
	if p.LifetimeCount == 0 {
		p.LifetimeCount = 10 * p.KeepAliveCount
	}
	if p.BufferSize <= 0 {
		p.BufferSize = 256
	}
	s := &Subscription{
		c:       c,
		params:  p,
		notify:  make(chan Notification, p.BufferSize),
		done:    make(chan struct{}),
		enabled: !p.Disabled,
		items:   map[uint32]*itemDef{},
	}
	if err := s.create(ctx); err != nil {
		return nil, err
	}
	if err := c.subs.add(s); err != nil {
		return nil, err
	}
	return s, nil
}

// create creates the subscription on the server (again, after the session
// was recreated) and resets the sequence numbers.
func (s *Subscription) create(ctx context.Context) error {
	p := s.params
	s.mu.Lock()
	enabled := s.enabled
	s.mu.Unlock()
	resp, err := call[*ua.CreateSubscriptionResponse](ctx, s.c, &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: float64(p.PublishingInterval) / float64(time.Millisecond),
		RequestedLifetimeCount:      p.LifetimeCount,
		RequestedMaxKeepAliveCount:  p.KeepAliveCount,
		MaxNotificationsPerPublish:  p.MaxNotificationsPerPublish,
		PublishingEnabled:           enabled,
		Priority:                    p.Priority,
	})
	if err != nil {
		return err
	}
	s.id.Store(resp.SubscriptionId)
	s.mu.Lock()
	s.interval = time.Duration(resp.RevisedPublishingInterval * float64(time.Millisecond))
	s.keepAliveCount = resp.RevisedMaxKeepAliveCount
	s.lifetimeCount = resp.RevisedLifetimeCount
	s.nextSeq = 1 // sequence numbers start at 1 (Part 4, 7.29)
	s.held = map[uint32]ua.NotificationMessage{}
	s.mu.Unlock()
	return nil
}

// ID returns the subscription id. It changes if the subscription is
// recreated after a reconnect.
func (s *Subscription) ID() uint32 { return s.id.Load() }

// PublishingInterval returns the publishing interval revised by the server.
func (s *Subscription) PublishingInterval() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.interval
}

// KeepAliveCount returns the keep-alive count revised by the server.
func (s *Subscription) KeepAliveCount() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keepAliveCount
}

// LifetimeCount returns the lifetime count revised by the server.
func (s *Subscription) LifetimeCount() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lifetimeCount
}

// MonitoredItems returns the subscription's monitored items. Their IDs
// change if the subscription is recreated after a reconnect; client handles
// stay the same.
func (s *Subscription) MonitoredItems() []MonitoredItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]MonitoredItem, 0, len(s.items))
	for h, d := range s.items {
		out = append(out, MonitoredItem{ID: d.id, ClientHandle: h, NodeID: d.req.ItemToMonitor.NodeId,
			AttributeID: d.req.ItemToMonitor.AttributeId})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientHandle < out[j].ClientHandle })
	return out
}

// Notifications returns the channel that receives the subscription's
// notifications in sequence number order. It is closed when the
// subscription is deleted, expires or the client is closed.
func (s *Subscription) Notifications() <-chan Notification { return s.notify }

// Monitor creates monitored items. Items with a zero ClientHandle get a
// handle assigned that is unique within the subscription.
func (s *Subscription) Monitor(ctx context.Context, ts ua.TimestampsToReturn, items ...ua.MonitoredItemCreateRequest) ([]MonitoredItem, error) {
	items = append([]ua.MonitoredItemCreateRequest(nil), items...)
	for i := range items {
		if items[i].RequestedParameters.ClientHandle == 0 {
			items[i].RequestedParameters.ClientHandle = s.nextHandle.Add(1)
		}
	}
	resp, err := s.createItems(ctx, ts, items)
	if err != nil {
		return nil, err
	}
	out := make([]MonitoredItem, len(items))
	for i, r := range resp.Results {
		out[i] = MonitoredItem{
			ID:               r.MonitoredItemId,
			ClientHandle:     items[i].RequestedParameters.ClientHandle,
			NodeID:           items[i].ItemToMonitor.NodeId,
			AttributeID:      items[i].ItemToMonitor.AttributeId,
			SamplingInterval: time.Duration(r.RevisedSamplingInterval * float64(time.Millisecond)),
			QueueSize:        r.RevisedQueueSize,
			Status:           r.StatusCode,
		}
	}
	return out, nil
}

// createItems creates monitored items and remembers the created ones.
func (s *Subscription) createItems(ctx context.Context, ts ua.TimestampsToReturn, items []ua.MonitoredItemCreateRequest) (*ua.CreateMonitoredItemsResponse, error) {
	resp, err := call[*ua.CreateMonitoredItemsResponse](ctx, s.c, &ua.CreateMonitoredItemsRequest{
		SubscriptionId: s.ID(), TimestampsToReturn: ts, ItemsToCreate: items,
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != len(items) {
		return nil, fmt.Errorf("client: CreateMonitoredItems returned %d results for %d items", len(resp.Results), len(items))
	}
	s.mu.Lock()
	for i, r := range resp.Results {
		if r.StatusCode.IsGood() {
			s.items[items[i].RequestedParameters.ClientHandle] = &itemDef{id: r.MonitoredItemId, ts: ts, req: items[i]}
		}
	}
	s.mu.Unlock()
	return resp, nil
}

// MonitorValues monitors the Value attribute of nodes, sampled at the
// publishing interval and reporting every change. Check the Status of each
// returned item.
func (s *Subscription) MonitorValues(ctx context.Context, nodeIDs ...ua.NodeId) ([]MonitoredItem, error) {
	items := make([]ua.MonitoredItemCreateRequest, len(nodeIDs))
	for i, id := range nodeIDs {
		items[i] = ua.MonitoredItemCreateRequest{
			ItemToMonitor:  ua.ReadValueId{NodeId: id, AttributeId: ua.AttributeIdValue},
			MonitoringMode: ua.MonitoringModeReporting,
			RequestedParameters: ua.MonitoringParameters{
				SamplingInterval: -1, // the publishing interval
				QueueSize:        1,
				DiscardOldest:    true,
			},
		}
	}
	return s.Monitor(ctx, ua.TimestampsToReturnBoth, items...)
}

// Unmonitor deletes monitored items.
func (s *Subscription) Unmonitor(ctx context.Context, ids ...uint32) error {
	resp, err := call[*ua.DeleteMonitoredItemsResponse](ctx, s.c, &ua.DeleteMonitoredItemsRequest{
		SubscriptionId: s.ID(), MonitoredItemIds: ids,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	for _, id := range ids {
		for h, d := range s.items {
			if d.id == id {
				delete(s.items, h)
			}
		}
	}
	s.mu.Unlock()
	for i, st := range resp.Results {
		if st.IsBad() && i < len(ids) {
			return fmt.Errorf("client: delete monitored item %d: %w", ids[i], st)
		}
	}
	return nil
}

// SetPublishingMode enables or disables publishing.
func (s *Subscription) SetPublishingMode(ctx context.Context, enabled bool) error {
	resp, err := call[*ua.SetPublishingModeResponse](ctx, s.c, &ua.SetPublishingModeRequest{
		PublishingEnabled: enabled, SubscriptionIds: []uint32{s.ID()},
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.enabled = enabled
	s.mu.Unlock()
	if len(resp.Results) == 1 && resp.Results[0].IsBad() {
		return fmt.Errorf("client: SetPublishingMode: %w", resp.Results[0])
	}
	return nil
}

// Delete deletes the subscription and closes its Notifications channel.
func (s *Subscription) Delete(ctx context.Context) error {
	s.c.subs.remove(s)
	defer s.close(nil)
	resp, err := call[*ua.DeleteSubscriptionsResponse](ctx, s.c, &ua.DeleteSubscriptionsRequest{SubscriptionIds: []uint32{s.ID()}})
	if err != nil {
		return err
	}
	if len(resp.Results) == 1 && resp.Results[0].IsBad() {
		return fmt.Errorf("client: DeleteSubscriptions: %w", resp.Results[0])
	}
	return nil
}

// close ends the subscription; err (if any) is sent as a last notification.
func (s *Subscription) close(err error) {
	s.closeOnce.Do(func() {
		close(s.done) // wakes a delivery waiting on a full channel
		s.deliverMu.Lock()
		defer s.deliverMu.Unlock()
		if err != nil {
			select {
			case s.notify <- Notification{SubscriptionID: s.ID(), Err: err}:
			default:
			}
		}
		close(s.notify)
	})
}

// receive handles a notification message from a Publish response. Messages
// are delivered in sequence number order: several Publish requests are
// outstanding, so their responses may be handled out of order.
func (s *Subscription) receive(msg ua.NotificationMessage) {
	if len(msg.NotificationData) == 0 {
		return // keep-alive
	}
	s.deliverMu.Lock()
	defer s.deliverMu.Unlock()
	select {
	case <-s.done:
		return
	default:
	}

	s.mu.Lock()
	if msg.SequenceNumber < s.nextSeq {
		s.mu.Unlock()
		return // duplicate
	}
	s.held[msg.SequenceNumber] = msg
	ready := s.takeReady()
	// A message that is still missing after several later ones arrived was
	// lost: ask the server to send it again.
	var missing []uint32
	if len(s.held) >= 3 {
		missing = s.missing()
	}
	s.mu.Unlock()

	for _, m := range ready {
		if !s.deliver(m) {
			return
		}
	}
	for _, seq := range missing {
		m, err := s.republish(seq)
		s.mu.Lock()
		if err == nil {
			s.held[seq] = m
		} else if seq == s.nextSeq {
			s.c.logf("client: subscription %d: notification %d lost: %v", s.ID(), seq, err)
			s.nextSeq++
		}
		ready = s.takeReady()
		s.mu.Unlock()
		for _, m := range ready {
			if !s.deliver(m) {
				return
			}
		}
	}
}

// recoverLost asks the server for notifications that were sent on a lost
// channel and delivers them.
func (s *Subscription) recoverLost() {
	s.deliverMu.Lock()
	defer s.deliverMu.Unlock()
	for range 100 {
		select {
		case <-s.done:
			return
		default:
		}
		s.mu.Lock()
		seq := s.nextSeq
		_, have := s.held[seq]
		s.mu.Unlock()
		if !have {
			m, err := s.republish(seq)
			if err != nil {
				return // BadMessageNotAvailable: nothing was lost
			}
			s.mu.Lock()
			s.held[seq] = m
			s.mu.Unlock()
		}
		s.mu.Lock()
		ready := s.takeReady()
		s.mu.Unlock()
		for _, m := range ready {
			if !s.deliver(m) {
				return
			}
		}
	}
}

// takeReady removes the held messages that can be delivered (called with mu held).
func (s *Subscription) takeReady() []ua.NotificationMessage {
	var ready []ua.NotificationMessage
	for {
		m, ok := s.held[s.nextSeq]
		if !ok {
			return ready
		}
		delete(s.held, s.nextSeq)
		ready = append(ready, m)
		s.nextSeq++
	}
}

// missing returns the sequence numbers before the newest held message that
// have not been received (called with mu held).
func (s *Subscription) missing() []uint32 {
	keys := make([]uint32, 0, len(s.held))
	for k := range s.held {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	var out []uint32
	for seq := s.nextSeq; seq < keys[len(keys)-1] && len(out) < 100; seq++ {
		if _, ok := s.held[seq]; !ok {
			out = append(out, seq)
		}
	}
	return out
}

func (s *Subscription) republish(seq uint32) (ua.NotificationMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.c.cfg.RequestTimeout)
	defer cancel()
	resp, err := call[*ua.RepublishResponse](ctx, s.c, &ua.RepublishRequest{SubscriptionId: s.ID(), RetransmitSequenceNumber: seq})
	if err != nil {
		return ua.NotificationMessage{}, err
	}
	return resp.NotificationMessage, nil
}

// deliver sends one message to the application (called with deliverMu held).
// It returns false if the subscription was closed.
func (s *Subscription) deliver(msg ua.NotificationMessage) bool {
	n := Notification{SubscriptionID: s.ID(), SequenceNumber: msg.SequenceNumber, PublishTime: msg.PublishTime}
	for _, eo := range msg.NotificationData {
		switch v := eo.Value.(type) {
		case *ua.DataChangeNotification:
			n.DataChanges = append(n.DataChanges, v.MonitoredItems...)
		case *ua.EventNotificationList:
			n.Events = append(n.Events, v.Events...)
		case *ua.StatusChangeNotification:
			n.StatusChange = v.Status
		}
	}
	select {
	case s.notify <- n:
	case <-s.done:
		return false
	}
	if n.StatusChange.IsBad() {
		// The subscription ended on the server (e.g. BadTimeout).
		s.c.subs.remove(s)
		go s.close(nil)
		return false
	}
	return true
}

// --- publishing ---

// subscriptions keeps Publish requests outstanding while the session has
// subscriptions and routes the responses.
type subscriptions struct {
	c *Client

	mu         sync.Mutex
	subs       map[uint32]*Subscription
	acks       []ua.SubscriptionAcknowledgement
	workers    int
	maxWorkers int
	err        error
}

func newSubscriptions(c *Client) *subscriptions {
	return &subscriptions{c: c, subs: map[uint32]*Subscription{}, maxWorkers: 4}
}

func (m *subscriptions) add(s *Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.subs[s.ID()] = s
	for m.workers < m.target() {
		m.workers++
		go m.worker()
	}
	return nil
}

func (m *subscriptions) remove(s *Subscription) {
	m.mu.Lock()
	if m.subs[s.ID()] == s {
		delete(m.subs, s.ID())
	}
	m.mu.Unlock()
}

// all returns the subscriptions.
func (m *subscriptions) all() []*Subscription {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Subscription, 0, len(m.subs))
	for _, s := range m.subs {
		out = append(out, s)
	}
	return out
}

// recover fetches notifications lost with the old channel, after the
// session was activated on a new one.
func (m *subscriptions) recover(ctx context.Context) {
	for _, s := range m.all() {
		go s.recoverLost()
	}
}

// recreate restores the subscriptions after the session was recreated:
// they are transferred from the old session if the server still has them,
// and created again otherwise (with the same client handles).
func (m *subscriptions) recreate(ctx context.Context) {
	subs := m.all()
	if len(subs) == 0 {
		return
	}
	ids := make([]uint32, len(subs))
	for i, s := range subs {
		ids[i] = s.ID()
	}
	transferred := make([]bool, len(subs))
	if resp, err := call[*ua.TransferSubscriptionsResponse](ctx, m.c, &ua.TransferSubscriptionsRequest{
		SubscriptionIds: ids, SendInitialValues: true,
	}); err == nil && len(resp.Results) == len(subs) {
		for i, r := range resp.Results {
			transferred[i] = r.StatusCode.IsGood()
		}
	}
	for i, s := range subs {
		if transferred[i] {
			m.c.logf("client: subscription %d transferred to the new session", ids[i])
			go s.recoverLost()
			continue
		}
		if err := m.recreateOne(ctx, s); err != nil {
			m.c.logf("client: recreating subscription %d: %v", ids[i], err)
			m.remove(s)
			s.close(fmt.Errorf("client: the subscription was lost when the session was recreated: %w", err))
		}
	}
}

func (m *subscriptions) recreateOne(ctx context.Context, s *Subscription) error {
	old := s.ID()
	s.deliverMu.Lock() // no delivery while the sequence numbers are reset
	err := s.create(ctx)
	s.deliverMu.Unlock()
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.subs[old] == s {
		delete(m.subs, old)
	}
	m.subs[s.ID()] = s
	for m.workers < m.target() {
		m.workers++
		go m.worker()
	}
	m.mu.Unlock()

	s.mu.Lock()
	byTS := map[ua.TimestampsToReturn][]ua.MonitoredItemCreateRequest{}
	for _, d := range s.items {
		byTS[d.ts] = append(byTS[d.ts], d.req)
	}
	s.items = map[uint32]*itemDef{}
	s.mu.Unlock()
	for ts, items := range byTS {
		resp, err := s.createItems(ctx, ts, items)
		if err != nil {
			return err
		}
		for i, r := range resp.Results {
			if r.StatusCode.IsBad() {
				m.c.logf("client: subscription %d: monitored item %d could not be recreated: %s",
					s.ID(), items[i].RequestedParameters.ClientHandle, r.StatusCode)
			}
		}
	}
	m.c.logf("client: subscription %d recreated as %d", old, s.ID())
	return nil
}

// target is the number of outstanding Publish requests (called with mu held).
func (m *subscriptions) target() int {
	if len(m.subs) == 0 {
		return 0
	}
	return min(len(m.subs)+1, m.maxWorkers)
}

func (m *subscriptions) shutdown(err error) {
	m.mu.Lock()
	if m.err == nil {
		m.err = err
	}
	subs := m.subs
	m.subs = map[uint32]*Subscription{}
	m.mu.Unlock()
	for _, s := range subs {
		s.close(err)
	}
}

// publishTimeout is how long a Publish request may wait for a notification
// (called with mu held).
func (m *subscriptions) publishTimeout() time.Duration {
	var longest time.Duration
	for _, s := range m.subs {
		s.mu.Lock()
		longest = max(longest, s.interval*time.Duration(max(s.keepAliveCount, 1)))
		s.mu.Unlock()
	}
	return longest + m.c.cfg.RequestTimeout
}

func (m *subscriptions) worker() {
	backoff := func(d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-m.c.closed:
			return false
		case <-t.C:
			return true
		}
	}
	for {
		m.mu.Lock()
		if m.err != nil || m.workers > m.target() {
			m.workers--
			m.mu.Unlock()
			return
		}
		acks := m.acks
		m.acks = nil
		timeout := m.publishTimeout()
		m.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		resp, err := m.c.send(ctx, &ua.PublishRequest{SubscriptionAcknowledgements: acks})
		cancel()
		if err != nil {
			m.mu.Lock()
			m.acks = append(acks, m.acks...)
			m.mu.Unlock()
			select {
			case <-m.c.closed:
				continue // the loop exits once shutdown has set m.err
			default:
			}
			switch {
			case errors.Is(err, ua.StatusBadTimeout), errors.Is(err, context.DeadlineExceeded):
			case errors.Is(err, ua.StatusBadNoSubscription):
				if !backoff(50 * time.Millisecond) {
					continue
				}
			case errors.Is(err, ua.StatusBadTooManyPublishRequests):
				m.mu.Lock()
				m.maxWorkers = max(m.workers-1, 1)
				m.mu.Unlock()
			case errors.Is(err, ua.StatusBadSessionIdInvalid), errors.Is(err, ua.StatusBadSessionClosed):
				m.c.logf("client: publish: %v", err)
				if m.c.cfg.AutoReconnect {
					// The server dropped the session: reconnecting recreates it.
					m.c.dropChannel()
					backoff(200 * time.Millisecond)
				} else {
					m.shutdown(err)
				}
			default:
				m.c.logf("client: publish: %v", err)
				backoff(200 * time.Millisecond)
			}
			continue
		}
		pr, ok := resp.(*ua.PublishResponse)
		if !ok {
			continue
		}
		m.mu.Lock()
		if len(pr.NotificationMessage.NotificationData) > 0 {
			m.acks = append(m.acks, ua.SubscriptionAcknowledgement{
				SubscriptionId: pr.SubscriptionId, SequenceNumber: pr.NotificationMessage.SequenceNumber,
			})
		}
		s := m.subs[pr.SubscriptionId]
		m.mu.Unlock()
		if s != nil {
			s.receive(pr.NotificationMessage)
		}
	}
}
