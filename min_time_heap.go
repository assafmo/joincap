package main

import (
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type packet struct {
	Timestamp             int64
	MinimumLegalTimestamp int64
	CaptureInfo           gopacket.CaptureInfo
	Data                  []byte
	Reader                *pcapgo.Reader
	InputFile             *os.File
}

type packetHeap []packet

func (h packetHeap) Len() int { return len(h) }
func (h packetHeap) Less(i, j int) bool {
	return h[i].Timestamp <= h[j].Timestamp
}
func (h packetHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

// Push use pointer receivers because they modify the slice's length,
// not just its contents.
func (h *packetHeap) Push(x interface{}) {
	*h = append(*h, x.(packet))
}

// Pop use pointer receivers because they modify the slice's length,
// not just its contents.
func (h *packetHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
