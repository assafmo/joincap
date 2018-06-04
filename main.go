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
	Verbose        bool   `short:"v" long:"verbose" description:"Explain when skiping packets or entire input files."`
	Version        bool   `short:"V" long:"version" description:"Print the version and exit."`
	OutputFilePath string `short:"w" default:"-" description:"Sets the output filename. If the name is '-', stdout will be used."`
}

func max(x, y uint32) uint32 {
	if x > y {
		return x
	}
	return y
}

const version = "0.5.0"

func main() {
	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:8080", nil))
	// }()

	restOfArgs, err := flags.ParseArgs(&opts, os.Args)

	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			// print version and help and exit
			fmt.Println("joincap v" + version)
			os.Exit(0)
		} else {
			panic(err)
		}
	}

	if opts.Version {
		// print version and exit
		fmt.Println("joincap v" + version)
		os.Exit(0)
	}
	if opts.Verbose {
		fmt.Println("joincap v" + version)
	}

	readers := make([]*pcapgo.Reader, 0)
	h := &PacketHeap{}
	heap.Init(h)

	outputFile := os.Stdout

	if opts.OutputFilePath != "-" {
		outputFile, err = os.Create(opts.OutputFilePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, opts.OutputFilePath+":")
			panic(err)
		}
		defer outputFile.Close()
	}
	bufferedWriter := bufio.NewWriter(outputFile)
	defer bufferedWriter.Flush()

	pcapWriter := pcapgo.NewWriter(bufferedWriter)

	var snaplen uint32
	var linkType layers.LinkType
	for _, pcapPath := range restOfArgs[1:] {
		f, err := os.Open(pcapPath)
		if err != nil {
			if opts.Verbose {
				fmt.Fprintln(os.Stderr, pcapPath+":", err, "(skiping)")
			}
			continue
		}
		defer f.Close()

		pcapReader, err := pcapgo.NewReader(f)
		if err != nil {
			if opts.Verbose {
				fmt.Fprintln(os.Stderr, pcapPath+":", err, "(skiping)")
			}
			continue
		}

		readers = append(readers, pcapReader)

		snaplen = max(snaplen, pcapReader.Snaplen())
		if linkType == layers.LinkTypeNull {
			linkType = pcapReader.LinkType()
		} else if linkType != pcapReader.LinkType() {
			log.Fatalln("Different LinkTypes:", linkType, pcapReader.LinkType())
		}

		for {
			data, captureInfo, err := pcapReader.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					break
				} else if opts.Verbose {
					// skip errors
					fmt.Fprintln(os.Stderr, pcapPath+":", err, "(skiping this packet)")
				}
			}
			h.Push(Packet{captureInfo, data, pcapReader, pcapPath})
			break
		}
	}

	pcapWriter.WriteFileHeader(snaplen, linkType)
	for {
		if h.Len() == 0 {
			break
		}

		// find earliest packet and write in to the output file
		packet := h.Pop().(Packet)
		err = pcapWriter.WritePacket(packet.CaptureInfo, packet.Data)
		if err != nil && opts.Verbose {
			// skip errors
			fmt.Fprintln(os.Stderr, err, "(skiping this packet)")
		}

		// read the next packet from the source of the written packet
		// and push it to the heap
		for {
			data, captureInfo, err := packet.Reader.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					break
				} else if opts.Verbose {
					// skip errors
					fmt.Fprintln(os.Stderr, packet.PcapPath+":", err, "(skiping this packet)")
				}
			}
			h.Push(Packet{captureInfo, data, packet.Reader, packet.PcapPath})
			break
		}
	}
}
