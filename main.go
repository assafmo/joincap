package main

import (
	"container/heap"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func max(x, y uint32) uint32 {
	if x > y {
		return x
	}
	return y
}

func main() {
	readers := make([]*pcapgo.Reader, 0)
	h := &PacketHeap{}
	heap.Init(h)

	w := pcapgo.NewWriter(os.Stdout)

	if len(os.Args) < 2 {
		fmt.Println("pcapcat <infile> [<infile>...]")
		os.Exit(1)
	}

	var snaplen uint32
	var linkType layers.LinkType
	for _, pcapPath := range os.Args[1:] {
		if pcapPath == "-h" || pcapPath == "--help" {
			fmt.Println("pcapcat <infile> [<infile>...]")
			os.Exit(0)
		}
		if pcapPath == "-v" || pcapPath == "--version" {
			fmt.Println("v0.1.0")
			os.Exit(0)
		}

		f, _ := os.Open(pcapPath)
		defer f.Close()

		pcapReader, err := pcapgo.NewReader(f)
		if err != nil {
			log.Fatal(err)
		}

		readers = append(readers, pcapReader)

		snaplen = max(snaplen, pcapReader.Snaplen())
		if linkType == layers.LinkTypeNull {
			linkType = pcapReader.LinkType()
		} else if linkType != pcapReader.LinkType() {
			log.Fatalln("Different LinkTypes:", linkType, pcapReader.LinkType())
		}

		data, captureInfo, err := pcapReader.ReadPacketData()
		if err == nil && err != io.EOF {
			// log.Fatalln("Error reading file", pcapPath, ":", err)
			h.Push(Packet{captureInfo, data, pcapReader})
		}
	}

	w.WriteFileHeader(snaplen, linkType)
	for {
		if h.Len() == 0 {
			break
		}

		packet := h.Pop().(Packet)
		w.WritePacket(packet.CaptureInfo, packet.Data)

		data, captureInfo, err := packet.Reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				continue
			}

			// log.Fatalln("Error reading file", packet.Reader, ":", err)
		}

		h.Push(Packet{captureInfo, data, packet.Reader})
	}
}
