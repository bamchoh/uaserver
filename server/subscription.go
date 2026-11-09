package server

import (
	"math"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"github.com/bamchoh/uaserver/ua"
	"github.com/bamchoh/uaserver/uasc"
)

const (
	maxPublishQueue   = 20
	maxRetransmission = 50
	maxQueueSize      = 1000
	maxInterval       = time.Hour
)

type publishReq struct {
	srv      *Server
	ch       *uasc.Channel
	reqID    uint32
	req      *ua.PublishRequest
	deadline time.Time
	results  []ua.StatusCode
}

func (p *publishReq) respond(resp ua.Structure) {
	p.srv.send(p.ch, p.reqID, &p.req.RequestHeader, resp)
}

type monitoredItem struct {
	id            uint32
	clientHandle  uint32
	rv            ua.ReadValueId
	mode          ua.MonitoringMode
	interval      time.Duration
	queueSize     uint32
	discardOldest bool
	ttr           ua.TimestampsToReturn
	trigger       ua.DataChangeTrigger
	deadband      float64 // absolute deadband, 0 = none

	nextSample time.Time
	last       ua.DataValue
	hasLast    bool
	queue      []ua.MonitoredItemNotification
}

type subscription struct {
	id   uint32
	srv  *Server
	sess atomic.Pointer[Session]

	// The fields below are protected by the owning session's mutex.
	interval       time.Duration
	lifetimeCount  uint32
	keepAliveCount uint32
	maxNotif       uint32
	priority       byte
	enabled        bool
	items          map[uint32]*monitoredItem
	nextItemID     uint32
	seq            uint32
	retrans        []ua.NotificationMessage
	keepAliveCtr   uint32
	lifetimeCtr    uint32
	late           bool
	firstCycle     bool
	nextPublish    time.Time
	statusChange   *ua.StatusChangeNotification

	stopCh  chan struct{}
	stopped atomic.Bool
}

func (sub *subscription) stop() {
	if sub.stopped.CompareAndSwap(false, true) {
		close(sub.stopCh)
	}
}

// lockSession locks the session currently owning the subscription.
func (sub *subscription) lockSession() *Session {
	for {
		s := sub.sess.Load()
		s.mu.Lock()
		if sub.sess.Load() == s {
			return s
		}
		s.mu.Unlock()
	}
}

func (sub *subscription) itemHandles() ([]uint32, []uint32) {
	s := sub.lockSession()
	defer s.mu.Unlock()
	ids := make([]uint32, 0, len(sub.items))
	for id := range sub.items {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	handles := make([]uint32, len(ids))
	for i, id := range ids {
		handles[i] = sub.items[id].clientHandle
	}
	return ids, handles
}

func (s *Server) reviseSubscription(sub *subscription, interval float64, lifetime, keepAlive, maxNotif uint32) {
	iv := time.Duration(interval * float64(time.Millisecond))
	if iv < s.cfg.MinPublishingInterval || math.IsNaN(interval) {
		iv = s.cfg.MinPublishingInterval
	}
	if iv > maxInterval {
		iv = maxInterval
	}
	if keepAlive == 0 {
		keepAlive = 10
	}
	if keepAlive > 10000 {
		keepAlive = 10000
	}
	if lifetime < 3*keepAlive {
		lifetime = 3 * keepAlive
	}
	if lifetime > 100000 {
		lifetime = 100000
	}
	sub.interval, sub.lifetimeCount, sub.keepAliveCount, sub.maxNotif = iv, lifetime, keepAlive, maxNotif
}

func (s *Server) createSubscription(sess *Session, r *ua.CreateSubscriptionRequest) ua.Structure {
	hdr := &r.RequestHeader
	sess.mu.Lock()
	if len(sess.subs) >= s.cfg.MaxSubscriptions {
		sess.mu.Unlock()
		return fault(hdr, ua.StatusBadTooManySubscriptions)
	}
	sub := &subscription{
		id: s.nextSubID.Add(1), srv: s, items: map[uint32]*monitoredItem{},
		priority: r.Priority, enabled: r.PublishingEnabled, firstCycle: true, stopCh: make(chan struct{}),
	}
	sub.sess.Store(sess)
	s.reviseSubscription(sub, r.RequestedPublishingInterval, r.RequestedLifetimeCount, r.RequestedMaxKeepAliveCount, r.MaxNotificationsPerPublish)
	sub.nextPublish = time.Now().Add(sub.interval)
	sess.subs[sub.id] = sub
	resp := &ua.CreateSubscriptionResponse{
		ResponseHeader:            respHeader(hdr, 0),
		SubscriptionId:            sub.id,
		RevisedPublishingInterval: float64(sub.interval) / float64(time.Millisecond),
		RevisedLifetimeCount:      sub.lifetimeCount,
		RevisedMaxKeepAliveCount:  sub.keepAliveCount,
	}
	sess.mu.Unlock()
	go sub.run()
	return resp
}

func (s *Server) modifySubscription(sess *Session, r *ua.ModifySubscriptionRequest) ua.Structure {
	hdr := &r.RequestHeader
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sub := sess.subs[r.SubscriptionId]
	if sub == nil {
		return fault(hdr, ua.StatusBadSubscriptionIdInvalid)
	}
	s.reviseSubscription(sub, r.RequestedPublishingInterval, r.RequestedLifetimeCount, r.RequestedMaxKeepAliveCount, r.MaxNotificationsPerPublish)
	sub.priority = r.Priority
	sub.nextPublish = time.Now().Add(sub.interval)
	return &ua.ModifySubscriptionResponse{
		ResponseHeader:            respHeader(hdr, 0),
		RevisedPublishingInterval: float64(sub.interval) / float64(time.Millisecond),
		RevisedLifetimeCount:      sub.lifetimeCount,
		RevisedMaxKeepAliveCount:  sub.keepAliveCount,
	}
}

func (s *Server) setPublishingMode(sess *Session, r *ua.SetPublishingModeRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.SubscriptionIds)); st != 0 {
		return fault(hdr, st)
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	results := make([]ua.StatusCode, len(r.SubscriptionIds))
	for i, id := range r.SubscriptionIds {
		sub := sess.subs[id]
		if sub == nil {
			results[i] = ua.StatusBadSubscriptionIdInvalid
			continue
		}
		sub.enabled = r.PublishingEnabled
	}
	return &ua.SetPublishingModeResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func (s *Server) deleteSubscriptions(sess *Session, r *ua.DeleteSubscriptionsRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.SubscriptionIds)); st != 0 {
		return fault(hdr, st)
	}
	sess.mu.Lock()
	results := make([]ua.StatusCode, len(r.SubscriptionIds))
	for i, id := range r.SubscriptionIds {
		sub := sess.subs[id]
		if sub == nil {
			results[i] = ua.StatusBadSubscriptionIdInvalid
			continue
		}
		delete(sess.subs, id)
		sub.stop()
	}
	pending := sess.takePublishIfNoSubsLocked()
	sess.mu.Unlock()
	for _, p := range pending {
		p.respond(fault(&p.req.RequestHeader, ua.StatusBadNoSubscription))
	}
	return &ua.DeleteSubscriptionsResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func (sess *Session) takePublishIfNoSubsLocked() []*publishReq {
	if len(sess.subs) > 0 {
		return nil
	}
	p := sess.publishQueue
	sess.publishQueue = nil
	return p
}

func (s *Server) transferSubscriptions(sess *Session, r *ua.TransferSubscriptionsRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.SubscriptionIds)); st != 0 {
		return fault(hdr, st)
	}
	results := make([]ua.TransferResult, len(r.SubscriptionIds))
	myIdentity := sess.Identity()
	for i, subID := range r.SubscriptionIds {
		var owner *Session
		var sub *subscription
		s.sessions.mu.Lock()
		for _, o := range s.sessions.sessions {
			o.mu.Lock()
			if x := o.subs[subID]; x != nil {
				owner, sub = o, x
			}
			o.mu.Unlock()
			if sub != nil {
				break
			}
		}
		s.sessions.mu.Unlock()
		if sub == nil {
			results[i] = ua.TransferResult{StatusCode: ua.StatusBadSubscriptionIdInvalid}
			continue
		}
		if owner != sess {
			oid := owner.Identity()
			if oid.Type != myIdentity.Type || oid.UserName != myIdentity.UserName {
				results[i] = ua.TransferResult{StatusCode: ua.StatusBadUserAccessDenied}
				continue
			}
			owner.mu.Lock()
			delete(owner.subs, subID)
			pending := owner.takePublishIfNoSubsLocked()
			owner.mu.Unlock()
			for _, p := range pending {
				p.respond(fault(&p.req.RequestHeader, ua.StatusBadNoSubscription))
			}
		}
		sess.mu.Lock()
		sess.subs[subID] = sub
		sub.sess.Store(sess)
		if r.SendInitialValues {
			for _, it := range sub.items {
				it.hasLast = false
				it.nextSample = time.Time{}
			}
		}
		var avail []uint32
		for _, m := range sub.retrans {
			avail = append(avail, m.SequenceNumber)
		}
		sess.mu.Unlock()
		results[i] = ua.TransferResult{AvailableSequenceNumbers: avail}
	}
	return &ua.TransferSubscriptionsResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

// --- monitored items ---

func (s *Server) validateItem(sess *Session, sub *subscription, rv ua.ReadValueId, p ua.MonitoringParameters, it *monitoredItem) ua.StatusCode {
	n := s.as.Node(rv.NodeId)
	if n == nil {
		return ua.StatusBadNodeIdUnknown
	}
	if rv.AttributeId == AttrValue {
		if n.Class != ua.NodeClassVariable {
			return ua.StatusBadAttributeIdInvalid
		}
		if n.AccessLevel&AccessCurrentRead == 0 {
			return ua.StatusBadNotReadable
		}
		if !isDefaultBinary(rv.DataEncoding) {
			return ua.StatusBadDataEncodingUnsupported
		}
	} else {
		if _, st := s.attributeValue(ReadContext{Session: sess}, n, rv.AttributeId); st != 0 {
			return st
		}
		if rv.DataEncoding.Name != "" {
			return ua.StatusBadDataEncodingInvalid
		}
	}
	if rv.IndexRange != "" {
		if _, err := parseNumericRange(rv.IndexRange); err != nil {
			return ua.StatusBadIndexRangeInvalid
		}
	}
	it.trigger = ua.DataChangeTriggerStatusValue
	it.deadband = 0
	switch f := p.Filter.Value.(type) {
	case nil:
	case *ua.DataChangeFilter:
		if rv.AttributeId != AttrValue {
			return ua.StatusBadFilterNotAllowed
		}
		if f.Trigger > ua.DataChangeTriggerStatusValueTimestamp {
			return ua.StatusBadDeadbandFilterInvalid
		}
		it.trigger = f.Trigger
		switch ua.DeadbandType(f.DeadbandType) {
		case ua.DeadbandTypeNone:
		case ua.DeadbandTypeAbsolute:
			if f.DeadbandValue < 0 {
				return ua.StatusBadDeadbandFilterInvalid
			}
			want := s.builtinOf(n.DataType)
			if !isNumericType(want) && !s.as.IsSubtype(n.DataType, ua.NewNumericNodeId(0, 26)) {
				return ua.StatusBadFilterNotAllowed
			}
			it.deadband = f.DeadbandValue
		default:
			return ua.StatusBadMonitoredItemFilterUnsupported
		}
	default:
		// Event filters and aggregate filters are not supported.
		return ua.StatusBadMonitoredItemFilterUnsupported
	}

	iv := time.Duration(p.SamplingInterval * float64(time.Millisecond))
	if p.SamplingInterval < 0 || math.IsNaN(p.SamplingInterval) {
		iv = sub.interval
	}
	if min := time.Duration(n.MinimumSamplingInterval * float64(time.Millisecond)); iv < min {
		iv = min
	}
	if iv < s.cfg.MinSamplingInterval {
		iv = s.cfg.MinSamplingInterval
	}
	if iv > maxInterval {
		iv = maxInterval
	}
	q := p.QueueSize
	if q == 0 {
		q = 1
	}
	if q > maxQueueSize {
		q = maxQueueSize
	}
	it.rv = rv
	it.clientHandle = p.ClientHandle
	it.interval = iv
	it.queueSize = q
	it.discardOldest = p.DiscardOldest
	if len(it.queue) > int(q) {
		it.queue = it.queue[len(it.queue)-int(q):]
	}
	return 0
}

func (s *Server) createMonitoredItems(sess *Session, r *ua.CreateMonitoredItemsRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.ItemsToCreate)); st != 0 {
		return fault(hdr, st)
	}
	if r.TimestampsToReturn < ua.TimestampsToReturnSource || r.TimestampsToReturn > ua.TimestampsToReturnNeither {
		return fault(hdr, ua.StatusBadTimestampsToReturnInvalid)
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sub := sess.subs[r.SubscriptionId]
	if sub == nil {
		return fault(hdr, ua.StatusBadSubscriptionIdInvalid)
	}
	results := make([]ua.MonitoredItemCreateResult, len(r.ItemsToCreate))
	for i, req := range r.ItemsToCreate {
		if len(sub.items) >= s.cfg.MaxMonitoredItems {
			results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.StatusBadTooManyMonitoredItems}
			continue
		}
		if req.MonitoringMode > ua.MonitoringModeReporting {
			results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.StatusBadMonitoringModeInvalid}
			continue
		}
		it := &monitoredItem{mode: req.MonitoringMode, ttr: r.TimestampsToReturn}
		if st := s.validateItem(sess, sub, req.ItemToMonitor, req.RequestedParameters, it); st != 0 {
			results[i] = ua.MonitoredItemCreateResult{StatusCode: st}
			continue
		}
		sub.nextItemID++
		it.id = sub.nextItemID
		sub.items[it.id] = it
		results[i] = ua.MonitoredItemCreateResult{
			MonitoredItemId:         it.id,
			RevisedSamplingInterval: float64(it.interval) / float64(time.Millisecond),
			RevisedQueueSize:        it.queueSize,
		}
	}
	return &ua.CreateMonitoredItemsResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func (s *Server) modifyMonitoredItems(sess *Session, r *ua.ModifyMonitoredItemsRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.ItemsToModify)); st != 0 {
		return fault(hdr, st)
	}
	if r.TimestampsToReturn < ua.TimestampsToReturnSource || r.TimestampsToReturn > ua.TimestampsToReturnNeither {
		return fault(hdr, ua.StatusBadTimestampsToReturnInvalid)
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sub := sess.subs[r.SubscriptionId]
	if sub == nil {
		return fault(hdr, ua.StatusBadSubscriptionIdInvalid)
	}
	results := make([]ua.MonitoredItemModifyResult, len(r.ItemsToModify))
	for i, req := range r.ItemsToModify {
		it := sub.items[req.MonitoredItemId]
		if it == nil {
			results[i] = ua.MonitoredItemModifyResult{StatusCode: ua.StatusBadMonitoredItemIdInvalid}
			continue
		}
		tmp := *it
		if st := s.validateItem(sess, sub, it.rv, req.RequestedParameters, &tmp); st != 0 {
			results[i] = ua.MonitoredItemModifyResult{StatusCode: st}
			continue
		}
		tmp.ttr = r.TimestampsToReturn
		*it = tmp
		results[i] = ua.MonitoredItemModifyResult{
			RevisedSamplingInterval: float64(it.interval) / float64(time.Millisecond),
			RevisedQueueSize:        it.queueSize,
		}
	}
	return &ua.ModifyMonitoredItemsResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func (s *Server) setMonitoringMode(sess *Session, r *ua.SetMonitoringModeRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.MonitoredItemIds)); st != 0 {
		return fault(hdr, st)
	}
	if r.MonitoringMode > ua.MonitoringModeReporting {
		return fault(hdr, ua.StatusBadMonitoringModeInvalid)
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sub := sess.subs[r.SubscriptionId]
	if sub == nil {
		return fault(hdr, ua.StatusBadSubscriptionIdInvalid)
	}
	results := make([]ua.StatusCode, len(r.MonitoredItemIds))
	for i, id := range r.MonitoredItemIds {
		it := sub.items[id]
		if it == nil {
			results[i] = ua.StatusBadMonitoredItemIdInvalid
			continue
		}
		if r.MonitoringMode == ua.MonitoringModeDisabled {
			it.queue = nil
			it.hasLast = false
		} else if it.mode == ua.MonitoringModeDisabled {
			it.nextSample = time.Time{}
		}
		it.mode = r.MonitoringMode
	}
	return &ua.SetMonitoringModeResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

func (s *Server) deleteMonitoredItems(sess *Session, r *ua.DeleteMonitoredItemsRequest) ua.Structure {
	hdr := &r.RequestHeader
	if st := s.checkOperations(len(r.MonitoredItemIds)); st != 0 {
		return fault(hdr, st)
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sub := sess.subs[r.SubscriptionId]
	if sub == nil {
		return fault(hdr, ua.StatusBadSubscriptionIdInvalid)
	}
	results := make([]ua.StatusCode, len(r.MonitoredItemIds))
	for i, id := range r.MonitoredItemIds {
		if sub.items[id] == nil {
			results[i] = ua.StatusBadMonitoredItemIdInvalid
			continue
		}
		delete(sub.items, id)
	}
	return &ua.DeleteMonitoredItemsResponse{ResponseHeader: respHeader(hdr, 0), Results: results}
}

// --- sampling ---

func numericValue(v any) (float64, bool) {
	switch x := v.(type) {
	case int8:
		return float64(x), true
	case byte:
		return float64(x), true
	case int16:
		return float64(x), true
	case uint16:
		return float64(x), true
	case int32:
		return float64(x), true
	case uint32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float32:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

func (it *monitoredItem) valueChanged(a, b ua.Variant) bool {
	if a.Type() != b.Type() || a.IsArray() != b.IsArray() {
		return true
	}
	if it.deadband > 0 {
		if !a.IsArray() {
			x, ok1 := numericValue(a.Value())
			y, ok2 := numericValue(b.Value())
			if ok1 && ok2 {
				return math.Abs(x-y) > it.deadband
			}
		} else {
			av, bv := reflect.ValueOf(a.Value()), reflect.ValueOf(b.Value())
			if av.Len() != bv.Len() {
				return true
			}
			for i := 0; i < av.Len(); i++ {
				x, ok1 := numericValue(av.Index(i).Interface())
				y, ok2 := numericValue(bv.Index(i).Interface())
				if !ok1 || !ok2 || math.Abs(x-y) > it.deadband {
					return true
				}
			}
			return false
		}
	}
	return !variantEqual(a, b)
}

func variantEqual(a, b ua.Variant) bool {
	if ta, ok := a.Value().(time.Time); ok {
		tb, ok := b.Value().(time.Time)
		return ok && ta.Equal(tb)
	}
	return reflect.DeepEqual(a.Value(), b.Value()) && reflect.DeepEqual(a.Dimensions(), b.Dimensions())
}

func (it *monitoredItem) changed(dv ua.DataValue) bool {
	if !it.hasLast {
		return true
	}
	if dv.Status != it.last.Status {
		return true
	}
	if it.trigger == ua.DataChangeTriggerStatus {
		return false
	}
	if it.valueChanged(it.last.Value, dv.Value) {
		return true
	}
	if it.trigger == ua.DataChangeTriggerStatusValueTimestamp {
		return !dv.SourceTimestamp.Equal(it.last.SourceTimestamp)
	}
	return false
}

const overflowBits = 0x0480 // InfoType=DataValue, Overflow

func (it *monitoredItem) enqueue(dv ua.DataValue) {
	n := ua.MonitoredItemNotification{ClientHandle: it.clientHandle, Value: applyTimestamps(dv, it.ttr)}
	if uint32(len(it.queue)) < it.queueSize {
		it.queue = append(it.queue, n)
		return
	}
	if it.discardOldest {
		it.queue = append(it.queue[1:], n)
		if it.queueSize > 1 {
			it.queue[0].Value.Status |= overflowBits
		}
	} else {
		if it.queueSize > 1 {
			n.Value.Status |= overflowBits
		}
		it.queue[len(it.queue)-1] = n
	}
}

func (sub *subscription) run() {
	tick := time.NewTicker(sub.srv.cfg.MinSamplingInterval)
	defer tick.Stop()
	for {
		select {
		case <-sub.stopCh:
			return
		case <-sub.srv.closed:
			return
		case now := <-tick.C:
			sub.sample(now)
			sub.publishCycle(now)
		}
	}
}

type sampleJob struct {
	it *monitoredItem
	rv ua.ReadValueId
}

func (sub *subscription) sample(now time.Time) {
	sess := sub.lockSession()
	var jobs []sampleJob
	for _, it := range sub.items {
		if it.mode == ua.MonitoringModeDisabled || now.Before(it.nextSample) {
			continue
		}
		next := it.nextSample.Add(it.interval)
		if next.Before(now) {
			next = now.Add(it.interval)
		}
		it.nextSample = next
		jobs = append(jobs, sampleJob{it, it.rv})
	}
	sess.mu.Unlock()
	if len(jobs) == 0 {
		return
	}
	values := make([]ua.DataValue, len(jobs))
	for i, j := range jobs {
		values[i] = sub.srv.readAttribute(ReadContext{Session: sess}, j.rv, ua.TimestampsToReturnBoth)
	}
	sess = sub.lockSession()
	defer sess.mu.Unlock()
	for i, j := range jobs {
		it := j.it
		if sub.items[it.id] != it || it.mode == ua.MonitoringModeDisabled {
			continue
		}
		dv := values[i]
		if it.changed(dv) {
			it.last = dv
			it.hasLast = true
			it.enqueue(dv)
		}
	}
}

func (sub *subscription) hasNotificationsLocked() bool {
	if sub.statusChange != nil {
		return true
	}
	if !sub.enabled {
		return false
	}
	for _, it := range sub.items {
		if it.mode == ua.MonitoringModeReporting && len(it.queue) > 0 {
			return true
		}
	}
	return false
}

// popPublishLocked takes the oldest publish request that has not expired.
func (sess *Session) popPublishLocked() *publishReq {
	if len(sess.publishQueue) == 0 {
		return nil
	}
	p := sess.publishQueue[0]
	sess.publishQueue = sess.publishQueue[1:]
	return p
}

func (sub *subscription) publishCycle(now time.Time) {
	sess := sub.lockSession()
	if now.Before(sub.nextPublish) {
		sess.mu.Unlock()
		return
	}
	sub.nextPublish = sub.nextPublish.Add(sub.interval)
	if sub.nextPublish.Before(now) {
		sub.nextPublish = now.Add(sub.interval)
	}

	var send func()
	if len(sess.publishQueue) == 0 {
		sub.lifetimeCtr++
	} else {
		sub.lifetimeCtr = 0
	}
	if sub.lifetimeCtr >= sub.lifetimeCount {
		// The subscription expired.
		delete(sess.subs, sub.id)
		sub.stop()
		pending := sess.takePublishIfNoSubsLocked()
		sess.mu.Unlock()
		sub.srv.logf("subscription %d expired", sub.id)
		for _, p := range pending {
			p.respond(fault(&p.req.RequestHeader, ua.StatusBadNoSubscription))
		}
		return
	}
	if sub.hasNotificationsLocked() {
		if p := sess.popPublishLocked(); p != nil {
			resp := sub.buildPublishLocked(p, now)
			send = func() { p.respond(resp) }
		} else {
			sub.late = true
		}
	} else {
		sub.keepAliveCtr++
		if sub.firstCycle || sub.keepAliveCtr >= sub.keepAliveCount {
			if p := sess.popPublishLocked(); p != nil {
				resp := sub.buildPublishLocked(p, now)
				send = func() { p.respond(resp) }
			} else {
				sub.late = true
			}
		}
	}
	sub.firstCycle = false
	sess.mu.Unlock()
	if send != nil {
		send()
	}
}

// buildPublishLocked creates a publish response (data or keep-alive) for p.
func (sub *subscription) buildPublishLocked(p *publishReq, now time.Time) *ua.PublishResponse {
	sub.keepAliveCtr = 0
	sub.lifetimeCtr = 0
	sub.late = false

	var data []ua.ExtensionObject
	more := false
	if sub.enabled {
		var notifs []ua.MonitoredItemNotification
		limit := int(sub.maxNotif)
		ids := make([]uint32, 0, len(sub.items))
		for id := range sub.items {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			it := sub.items[id]
			if it.mode != ua.MonitoringModeReporting || len(it.queue) == 0 {
				continue
			}
			take := len(it.queue)
			if limit > 0 && len(notifs)+take > limit {
				take = limit - len(notifs)
				more = true
			}
			notifs = append(notifs, it.queue[:take]...)
			it.queue = it.queue[take:]
			if limit > 0 && len(notifs) >= limit {
				for _, rest := range ids {
					if len(sub.items[rest].queue) > 0 && sub.items[rest].mode == ua.MonitoringModeReporting {
						more = true
					}
				}
				break
			}
		}
		if len(notifs) > 0 {
			data = append(data, ua.NewExtensionObject(&ua.DataChangeNotification{MonitoredItems: notifs}))
		}
	}
	if sub.statusChange != nil {
		data = append(data, ua.NewExtensionObject(sub.statusChange))
		sub.statusChange = nil
	}
	msg := ua.NotificationMessage{PublishTime: now}
	if len(data) == 0 {
		msg.SequenceNumber = sub.seq + 1 // keep-alive: next sequence number, not consumed
		msg.NotificationData = []ua.ExtensionObject{}
	} else {
		sub.seq++
		if sub.seq == 0 {
			sub.seq = 1
		}
		msg.SequenceNumber = sub.seq
		msg.NotificationData = data
		sub.retrans = append(sub.retrans, msg)
		if len(sub.retrans) > maxRetransmission {
			sub.retrans = sub.retrans[len(sub.retrans)-maxRetransmission:]
		}
	}
	if more {
		sub.late = true
	}
	avail := make([]uint32, 0, len(sub.retrans))
	for _, m := range sub.retrans {
		avail = append(avail, m.SequenceNumber)
	}
	results := p.results
	if results == nil {
		results = []ua.StatusCode{}
	}
	return &ua.PublishResponse{
		ResponseHeader:           respHeader(&p.req.RequestHeader, 0),
		SubscriptionId:           sub.id,
		AvailableSequenceNumbers: avail,
		MoreNotifications:        more,
		NotificationMessage:      msg,
		Results:                  results,
	}
}

func (sess *Session) queuePublish(ch *uasc.Channel, reqID uint32, r *ua.PublishRequest) {
	p := &publishReq{srv: sess.srv, ch: ch, reqID: reqID, req: r}
	if r.RequestHeader.TimeoutHint > 0 {
		p.deadline = time.Now().Add(time.Duration(r.RequestHeader.TimeoutHint) * time.Millisecond)
	}
	sess.mu.Lock()
	if len(sess.subs) == 0 {
		sess.mu.Unlock()
		p.respond(fault(&r.RequestHeader, ua.StatusBadNoSubscription))
		return
	}
	p.results = make([]ua.StatusCode, len(r.SubscriptionAcknowledgements))
	for i, ack := range r.SubscriptionAcknowledgements {
		sub := sess.subs[ack.SubscriptionId]
		if sub == nil {
			p.results[i] = ua.StatusBadSubscriptionIdInvalid
			continue
		}
		p.results[i] = ua.StatusBadSequenceNumberUnknown
		for j, m := range sub.retrans {
			if m.SequenceNumber == ack.SequenceNumber {
				sub.retrans = append(sub.retrans[:j], sub.retrans[j+1:]...)
				p.results[i] = 0
				break
			}
		}
	}
	// Serve a late subscription immediately (highest priority first).
	var late *subscription
	for _, sub := range sess.subs {
		if sub.late && (late == nil || sub.priority > late.priority) {
			late = sub
		}
	}
	if late != nil {
		resp := late.buildPublishLocked(p, time.Now())
		sess.mu.Unlock()
		p.respond(resp)
		return
	}
	var dropped *publishReq
	if len(sess.publishQueue) >= maxPublishQueue {
		dropped = sess.publishQueue[0]
		sess.publishQueue = sess.publishQueue[1:]
	}
	sess.publishQueue = append(sess.publishQueue, p)
	for _, sub := range sess.subs {
		sub.lifetimeCtr = 0
	}
	sess.mu.Unlock()
	if dropped != nil {
		dropped.respond(fault(&dropped.req.RequestHeader, ua.StatusBadTooManyPublishRequests))
	}
}

func (sess *Session) expirePublishRequests(now time.Time) {
	sess.mu.Lock()
	var expired []*publishReq
	kept := sess.publishQueue[:0]
	for _, p := range sess.publishQueue {
		if !p.deadline.IsZero() && now.After(p.deadline) {
			expired = append(expired, p)
		} else {
			kept = append(kept, p)
		}
	}
	sess.publishQueue = kept
	sess.mu.Unlock()
	for _, p := range expired {
		p.respond(fault(&p.req.RequestHeader, ua.StatusBadTimeout))
	}
}

func (s *Server) republish(sess *Session, r *ua.RepublishRequest) ua.Structure {
	hdr := &r.RequestHeader
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sub := sess.subs[r.SubscriptionId]
	if sub == nil {
		return fault(hdr, ua.StatusBadSubscriptionIdInvalid)
	}
	for _, m := range sub.retrans {
		if m.SequenceNumber == r.RetransmitSequenceNumber {
			return &ua.RepublishResponse{ResponseHeader: respHeader(hdr, 0), NotificationMessage: m}
		}
	}
	return fault(hdr, ua.StatusBadMessageNotAvailable)
}
