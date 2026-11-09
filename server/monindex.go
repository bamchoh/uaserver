package server

import (
	"sync"
	"time"

	"github.com/bamchoh/uaserver/ua"
)

// monitorIndex maps variables to the monitored items that watch their Value
// attribute, so that a value change can be reported without waiting for the
// next sampling cycle. Its mutex is a leaf lock: no other lock is taken while
// it is held.
type monitorIndex struct {
	mu     sync.Mutex
	byNode map[ua.NodeId]map[*monitoredItem]*subscription
	bySub  map[*subscription]map[*monitoredItem]ua.NodeId
}

func newMonitorIndex() *monitorIndex {
	return &monitorIndex{
		byNode: map[ua.NodeId]map[*monitoredItem]*subscription{},
		bySub:  map[*subscription]map[*monitoredItem]ua.NodeId{},
	}
}

func (m *monitorIndex) add(sub *subscription, it *monitoredItem, nid ua.NodeId) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byNode[nid] == nil {
		m.byNode[nid] = map[*monitoredItem]*subscription{}
	}
	m.byNode[nid][it] = sub
	if m.bySub[sub] == nil {
		m.bySub[sub] = map[*monitoredItem]ua.NodeId{}
	}
	m.bySub[sub][it] = nid
}

func (m *monitorIndex) remove(sub *subscription, it *monitoredItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	nid, ok := m.bySub[sub][it]
	if !ok {
		return
	}
	delete(m.bySub[sub], it)
	if len(m.bySub[sub]) == 0 {
		delete(m.bySub, sub)
	}
	delete(m.byNode[nid], it)
	if len(m.byNode[nid]) == 0 {
		delete(m.byNode, nid)
	}
}

func (m *monitorIndex) removeSub(sub *subscription) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for it, nid := range m.bySub[sub] {
		delete(m.byNode[nid], it)
		if len(m.byNode[nid]) == 0 {
			delete(m.byNode, nid)
		}
	}
	delete(m.bySub, sub)
}

// lookup returns the items watching nid, grouped by subscription.
func (m *monitorIndex) lookup(nid ua.NodeId) map[*subscription][]*monitoredItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := m.byNode[nid]
	if len(items) == 0 {
		return nil
	}
	out := make(map[*subscription][]*monitoredItem, 1)
	for it, sub := range items {
		out[sub] = append(out[sub], it)
	}
	return out
}

// valueChanged is called by the address space after a variable value changed.
func (s *Server) valueChanged(nid ua.NodeId) {
	now := time.Now()
	for sub, items := range s.monitors.lookup(nid) {
		if sub.sampleItems(now, items) {
			sub.wakeUp()
		}
	}
}
