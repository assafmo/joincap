package minheap

import (
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// Packet is used by PacketHeap to order packets by timestamp
// and by joincap to merge pcaps
type Packet struct {
	Timestamp             int64
	MinimumLegalTimestamp int64
	CaptureInfo           gopacket.CaptureInfo
	Data                  []byte
	Reader                *pcapgo.Reader
	InputFile             *os.File
}

// PacketHeap is a minimum heap of packets ordered by timestamp
type PacketHeap []Packet

func (h PacketHeap) Len() int           { return len(h) }
func (h PacketHeap) Less(i, j int) bool { return h[i].Timestamp <= h[j].Timestamp }
func (h PacketHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

// Push use pointer receivers because they modify the slice's length,
// not just its contents.
func (h *PacketHeap) Push(x interface{}) { *h = append(*h, x.(Packet)) }

// Pop use pointer receivers because they modify the slice's length,
// not just its contents.
func (h *PacketHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
