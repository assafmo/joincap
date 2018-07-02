package minheap

import (
	"container/heap"
	"testing"
)

func TestLen(t *testing.T) {
	minTimeHeap := PacketHeap{}
	heap.Init(&minTimeHeap)

	if minTimeHeap.Len() != 0 {
		t.Fatal("minTimeHeap.Len() != 0", minTimeHeap.Len())
	}

	heap.Push(&minTimeHeap, Packet{})

	if minTimeHeap.Len() != 1 {
		t.Fatal("minTimeHeap.Len() != 1", minTimeHeap.Len())
	}

	heap.Push(&minTimeHeap, Packet{})

	if minTimeHeap.Len() != 2 {
		t.Fatal("minTimeHeap.Len() != 2", minTimeHeap.Len())
	}

	heap.Pop(&minTimeHeap)

	if minTimeHeap.Len() != 1 {
		t.Fatal("minTimeHeap.Len() != 1", minTimeHeap.Len())
	}

	heap.Pop(&minTimeHeap)

	if minTimeHeap.Len() != 0 {
		t.Fatal("minTimeHeap.Len() != 0", minTimeHeap.Len())
	}
}

func TestOrder(t *testing.T) {
	minTimeHeap := PacketHeap{}
	heap.Init(&minTimeHeap)

	heap.Push(&minTimeHeap, Packet{Timestamp: 10})
	heap.Push(&minTimeHeap, Packet{Timestamp: 2})
	heap.Push(&minTimeHeap, Packet{Timestamp: 5})
	heap.Push(&minTimeHeap, Packet{Timestamp: 3})
	heap.Push(&minTimeHeap, Packet{Timestamp: 12})

	two := heap.Pop(&minTimeHeap).(Packet)
	three := heap.Pop(&minTimeHeap).(Packet)
	five := heap.Pop(&minTimeHeap).(Packet)
	ten := heap.Pop(&minTimeHeap).(Packet)
	twelve := heap.Pop(&minTimeHeap).(Packet)

	if two.Timestamp != 2 {
		t.Fatal("two.Timestamp != 2", two.Timestamp)
	}
	if three.Timestamp != 3 {
		t.Fatal("two.Timestamp != 3", three.Timestamp)
	}
	if five.Timestamp != 5 {
		t.Fatal("two.Timestamp != 5", five.Timestamp)
	}
	if ten.Timestamp != 10 {
		t.Fatal("two.Timestamp != 10", ten.Timestamp)
	}
	if twelve.Timestamp != 12 {
		t.Fatal("two.Timestamp != 12", twelve.Timestamp)
	}
}
