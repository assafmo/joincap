package main

import (
	"bufio"
	"container/heap"
	"fmt"
	"io"
	// "log"
	// "net/http"
	// _ "net/http/pprof"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jessevdk/go-flags"
)

var opts struct {
	Verbose        bool   `short:"v" long:"verbose" description:"Explain when skipping packets or entire input files."`
	Version        bool   `short:"V" long:"version" description:"Print the version and exit."`
	OutputFilePath string `short:"w" default:"-" description:"Sets the output filename. If the name is '-', stdout will be used."`
	Rest           struct {
		InFiles []string
	} `positional-args:"yes" required:"yes"`
}

func max(x, y uint32) uint32 {
	if x > y {
		return x
	}
	return y
}

const version = "0.7.4"

func main() {
	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:8080", nil))
	// }()

	_, err := flags.ParseArgs(&opts, os.Args)

	// if -h or -V then print to stdout and exit
	// else print messages to stderr (avoids conflicts with outputFile)
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
		fmt.Fprintln(os.Stderr, "joincap v"+version)
	}

	minTimeHeap := &PacketHeap{}
	heap.Init(minTimeHeap)

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

	var totalInputSizeBytes int64
	var snaplen uint32
	var linkType layers.LinkType
	for _, pcapPath := range opts.Rest.InFiles[1:] {
		f, err := os.Open(pcapPath)
		if err != nil {
			if opts.Verbose {
				fmt.Fprintln(os.Stderr, pcapPath+":", err, "(skipping this file)")
			}
			continue
		}
		defer f.Close()

		fStat, _ := f.Stat()
		totalInputSizeBytes += fStat.Size()

		pcapReader, err := pcapgo.NewReader(f)
		if err != nil {
			if opts.Verbose {
				fmt.Fprintln(os.Stderr, pcapPath+":", err, "(skipping this file)")
			}
			continue
		}

		snaplen = max(snaplen, pcapReader.Snaplen())
		if linkType == layers.LinkTypeNull {
			linkType = pcapReader.LinkType()
		} else if linkType != pcapReader.LinkType() {
			panic(fmt.Sprintln(pcapPath+":", "Different LinkTypes:", linkType, pcapReader.LinkType()))
		}

		for {
			data, captureInfo, err := pcapReader.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					break
				}
				if opts.Verbose {
					fmt.Fprintln(os.Stderr, pcapPath+":", err, "(skipping this packet)")
				}
				// skip errors
				continue
			}
			heap.Push(minTimeHeap, Packet{&captureInfo, &data, pcapReader, &pcapPath})
			break
		}
	}

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "merging %d input files of size %f GiB\n", minTimeHeap.Len(), float64(totalInputSizeBytes)/1024/1024/1024)
		fmt.Fprintf(os.Stderr, "writing to %s\n", outputFile.Name())
	}

	pcapWriter.WriteFileHeader(snaplen, linkType)
	for minTimeHeap.Len() > 0 {
		// find the earliest packet and write it to the output file
		packet := heap.Pop(minTimeHeap).(Packet)
		write(pcapWriter, packet.CaptureInfo, packet.Data)

		// read the next packet from the source of the last written packet.
		// if this is the earliest packet, write it to the output file
		// else push it to the heap
		var earliestHeapTime int64
		if minTimeHeap.Len() > 0 {
			earliestHeapTime = (*minTimeHeap)[0].CaptureInfo.Timestamp.UnixNano()
		}
		for {
			data, captureInfo, err := packet.Reader.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					break
				}
				if opts.Verbose {
					fmt.Fprintln(os.Stderr, *packet.PcapPath+":", err, "(skipping this packet)")
				}
				// skip errors
				continue
			}

			if captureInfo.Timestamp.UnixNano() <= earliestHeapTime {
				write(pcapWriter, &captureInfo, &data)
				continue
			}

			heap.Push(minTimeHeap, Packet{&captureInfo, &data, packet.Reader, packet.PcapPath})
			break
		}
	}
}

func write(pcapWriter *pcapgo.Writer, captureInfo *gopacket.CaptureInfo, data *[]byte) {
	err := pcapWriter.WritePacket(*captureInfo, *data)
	if err != nil && opts.Verbose {
		fmt.Fprintln(os.Stderr, err, "(skipping this packet)")
		// skip errors
	}
}
