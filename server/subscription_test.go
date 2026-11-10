package server

import (
	"testing"
	"time"

	"github.com/bamchoh/uastack/ua"
)

// subscribe creates a subscription with one monitored item on nid and waits
// until the item's initial value has been sampled.
func subscribe(t *testing.T, s *Server, sess *Session, nid ua.NodeId, samplingMs float64) (*subscription, *monitoredItem) {
	t.Helper()
	cs := s.createSubscription(sess, &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: 1000, RequestedMaxKeepAliveCount: 10, RequestedLifetimeCount: 100,
		PublishingEnabled: true,
	}).(*ua.CreateSubscriptionResponse)
	sess.mu.Lock()
	sub := sess.subs[cs.SubscriptionId]
	sess.mu.Unlock()
	t.Cleanup(sub.stop)
	cr := s.createMonitoredItems(sess, &ua.CreateMonitoredItemsRequest{
		SubscriptionId: cs.SubscriptionId, TimestampsToReturn: ua.TimestampsToReturnBoth,
		ItemsToCreate: []ua.MonitoredItemCreateRequest{{
			ItemToMonitor:       ua.ReadValueId{NodeId: nid, AttributeId: AttrValue},
			MonitoringMode:      ua.MonitoringModeReporting,
			RequestedParameters: ua.MonitoringParameters{ClientHandle: 7, SamplingInterval: samplingMs, QueueSize: 10},
		}},
	}).(*ua.CreateMonitoredItemsResponse)
	if st := cr.Results[0].StatusCode; st != 0 {
		t.Fatalf("create monitored item: %s", st)
	}
	sess.mu.Lock()
	it := sub.items[cr.Results[0].MonitoredItemId]
	sess.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sess.mu.Lock()
		ok := it.hasLast
		sess.mu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial value was not sampled")
		}
		time.Sleep(time.Millisecond)
	}
	return sub, it
}

// takeQueue removes and returns the queued values of an item.
func takeQueue(sess *Session, it *monitoredItem) []int32 {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	var out []int32
	for _, n := range it.queue {
		out = append(out, n.Value.Value.Value().(int32))
	}
	it.queue = nil
	return out
}

func TestValueChangeIsReportedImmediately(t *testing.T) {
	s := newTestServer(t)
	ns := s.as.RegisterNamespace("urn:test")
	nid := ua.NewStringNodeId(ns, "v")
	if _, err := s.as.AddVariable(ObjectsFolder, nid, ua.NewQualifiedName(ns, "v"), ua.NewVariant(int32(0)), VariableOptions{}); err != nil {
		t.Fatal(err)
	}
	sess := &Session{srv: s, subs: map[uint32]*subscription{}, browseCPs: map[string]*browseCP{}}

	sub, it := subscribe(t, s, sess, nid, 0)
	if !it.eventDriven || it.interval != 0 {
		t.Fatalf("expected an event driven item with interval 0, got %v %s", it.eventDriven, it.interval)
	}
	if got := takeQueue(sess, it); len(got) != 1 || got[0] != 0 {
		t.Fatalf("initial value: %v", got)
	}
	// The change is queued synchronously by SetValue, without waiting for polling.
	for v := int32(1); v <= 3; v++ {
		if err := s.as.SetValue(nid, ua.NewVariant(v)); err != nil {
			t.Fatal(err)
		}
	}
	if got := takeQueue(sess, it); len(got) != 3 || got[2] != 3 {
		t.Fatalf("queued values after SetValue: %v", got)
	}
	// After the subscription is deleted, changes are no longer delivered to it.
	sub.stop()
	_ = s.as.SetValue(nid, ua.NewVariant(int32(4)))
	if got := takeQueue(sess, it); len(got) != 0 {
		t.Fatalf("value delivered after stop: %v", got)
	}
}

func TestSamplingIntervalLimitsReportedChanges(t *testing.T) {
	s := newTestServer(t)
	ns := s.as.RegisterNamespace("urn:test")
	nid := ua.NewStringNodeId(ns, "v")
	if _, err := s.as.AddVariable(ObjectsFolder, nid, ua.NewQualifiedName(ns, "v"), ua.NewVariant(int32(0)), VariableOptions{}); err != nil {
		t.Fatal(err)
	}
	sess := &Session{srv: s, subs: map[uint32]*subscription{}, browseCPs: map[string]*browseCP{}}
	_, it := subscribe(t, s, sess, nid, 300)
	takeQueue(sess, it)

	// Within the 300 ms sampling interval a change is deferred, then sampled once.
	_ = s.as.SetValue(nid, ua.NewVariant(int32(1)))
	_ = s.as.SetValue(nid, ua.NewVariant(int32(2)))
	if got := takeQueue(sess, it); len(got) != 0 {
		t.Fatalf("changes within the sampling interval were reported at once: %v", got)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := takeQueue(sess, it); len(got) > 0 {
			if len(got) != 1 || got[0] != 2 {
				t.Fatalf("deferred sample: %v", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("deferred change was never sampled")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestOnReadValuesArePolled(t *testing.T) {
	s := newTestServer(t)
	ns := s.as.RegisterNamespace("urn:test")
	nid := ua.NewStringNodeId(ns, "v")
	n, err := s.as.AddVariable(ObjectsFolder, nid, ua.NewQualifiedName(ns, "v"), ua.NewVariant(int32(0)), VariableOptions{})
	if err != nil {
		t.Fatal(err)
	}
	n.OnRead = func(ReadContext) ua.DataValue { return ua.NewDataValue(ua.NewVariant(int32(5))) }
	sess := &Session{srv: s, subs: map[uint32]*subscription{}, browseCPs: map[string]*browseCP{}}
	_, it := subscribe(t, s, sess, nid, 0)
	if it.eventDriven || it.interval < s.cfg.MinSamplingInterval {
		t.Fatalf("OnRead values must be polled at MinSamplingInterval, got event driven=%v interval=%s", it.eventDriven, it.interval)
	}
}
