package client

import (
	"testing"

	"github.com/bamchoh/uaserver/ua"
)

func dataMsg(seq uint32, v int32) ua.NotificationMessage {
	return ua.NotificationMessage{SequenceNumber: seq, NotificationData: []ua.ExtensionObject{
		ua.NewExtensionObject(&ua.DataChangeNotification{MonitoredItems: []ua.MonitoredItemNotification{
			{ClientHandle: 1, Value: ua.NewDataValue(ua.NewVariant(v))},
		}}),
	}}
}

// Publish responses handled out of order are delivered in sequence order.
func TestNotificationsAreReordered(t *testing.T) {
	s := &Subscription{
		notify: make(chan Notification, 10), done: make(chan struct{}),
		nextSeq: 1, held: map[uint32]ua.NotificationMessage{},
	}
	s.receive(dataMsg(2, 20))
	if len(s.notify) != 0 {
		t.Fatal("message 2 was delivered before message 1")
	}
	s.receive(ua.NotificationMessage{SequenceNumber: 3}) // keep-alive: ignored
	s.receive(dataMsg(1, 10))
	s.receive(dataMsg(1, 10)) // duplicate: ignored
	s.receive(dataMsg(3, 30))
	for _, want := range []uint32{1, 2, 3} {
		n := <-s.notify
		if n.SequenceNumber != want || n.DataChanges[0].Value.Value.Value() != int32(want*10) {
			t.Fatalf("got notification %d (%v), want %d", n.SequenceNumber, n.DataChanges[0].Value.Value, want)
		}
	}
	if len(s.notify) != 0 {
		t.Fatalf("%d unexpected notifications", len(s.notify))
	}
	s.close(nil)
	s.receive(dataMsg(4, 40)) // after close: must not panic
}
