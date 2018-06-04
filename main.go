package main

import (
	"bufio"
	"container/heap"
	"fmt"
	"io"
	"log"
	// "net/http"
	// _ "net/http/pprof"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jessevdk/go-flags"
)

var opts struct {
	Version        bool   `short:"v" long:"version" description:"Print version and exit"`
	OutputFilePath string `short:"w" default:"-" description:"File to output the merged pcap"`
}

func max(x, y uint32) uint32 {
	if x > y {
		return x
	}
	return y
}

func dieOnError(err error, path string) {
	if err != nil {
		fmt.Fprintln(os.Stderr, path)
		panic(err)
	}
}

func main() {
	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:8080", nil))
	// }()

	restOfArgs, err := flags.ParseArgs(&opts, os.Args)
	dieOnError(err, "")

	if opts.Version {
		fmt.Println("joincap v0.3.0")
		os.Exit(0)
	}

	readers := make([]*pcapgo.Reader, 0)
	h := &PacketHeap{}
	heap.Init(h)

	outputFile := os.Stdout

	if opts.OutputFilePath != "-" {
		outputFile, err = os.Create(opts.OutputFilePath)
		dieOnError(err, opts.OutputFilePath)
		defer outputFile.Close()
	}
	bufferedWriter := bufio.NewWriter(outputFile)
	defer bufferedWriter.Flush()

	pcapWriter := pcapgo.NewWriter(bufferedWriter)

	var snaplen uint32
	var linkType layers.LinkType
	for _, pcapPath := range restOfArgs[1:] {
		f, err := os.Open(pcapPath)
		dieOnError(err, pcapPath)
		defer f.Close()

		pcapReader, err := pcapgo.NewReader(f)
		dieOnError(err, pcapPath)

		readers = append(readers, pcapReader)

		snaplen = max(snaplen, pcapReader.Snaplen())
		if linkType == layers.LinkTypeNull {
			linkType = pcapReader.LinkType()
		} else if linkType != pcapReader.LinkType() {
			log.Fatalln("Different LinkTypes:", linkType, pcapReader.LinkType())
		}

		data, captureInfo, err := pcapReader.ReadPacketData()
		if err == nil && err != io.EOF {
			h.Push(Packet{captureInfo, data, pcapReader})
		}
	}

	pcapWriter.WriteFileHeader(snaplen, linkType)
	for {
		if h.Len() == 0 {
			break
		}

		// find earliest packet to write
		packet := h.Pop().(Packet)
		err = pcapWriter.WritePacket(packet.CaptureInfo, packet.Data)
		if err != nil {
			// skip errors
			fmt.Fprintln(os.Stderr, err)
		}

		// read the next packet from the written packet source
		for {
			data, captureInfo, err := packet.Reader.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					break
				} else {
					// skip errors
					fmt.Fprintln(os.Stderr, err)
				}
			}
			h.Push(Packet{captureInfo, data, packet.Reader})
			break
		}
	}
}
