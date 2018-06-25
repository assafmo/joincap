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

	"github.com/assafmo/gopacket/pcapgo"
	"github.com/google/gopacket/layers"
	flags "github.com/jessevdk/go-flags"
)

const version = "0.8.4"

func main() {
	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:8080", nil))
	// }()

	joincap(os.Args)
}

func joincap(args []string) {
	var cmdFlags struct {
		Verbose        bool   `short:"v" long:"verbose" description:"Explain when skipping packets or entire input files."`
		Version        bool   `short:"V" long:"version" description:"Print the version and exit."`
		OutputFilePath string `short:"w" default:"-" description:"Sets the output filename. If the name is '-', stdout will be used."`
		Rest           struct {
			InFiles []string
		} `positional-args:"yes" required:"yes"`
	}

	_, err := flags.ParseArgs(&cmdFlags, args)

	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			// -h flasg, print version and help and exit
			fmt.Printf("joincap v%s\n", version)
			os.Exit(0)
		} else {
			panic(err)
		}
	}

	if cmdFlags.Version {
		// -v flag, print version and exit
		fmt.Printf("joincap v%s\n", version)
		os.Exit(0)
	}
	if cmdFlags.Verbose {
		fmt.Fprintf(os.Stderr, "joincap v%s\n", version)
	}

	minTimeHeap := packetHeap{}
	heap.Init(&minTimeHeap)

	outputFile := os.Stdout
	if cmdFlags.OutputFilePath != "-" {
		outputFile, err = os.Create(cmdFlags.OutputFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", cmdFlags.OutputFilePath, err)
			panic(err)
		}
		defer outputFile.Close()
	}
	bufferedFileWriter := bufio.NewWriter(outputFile)
	defer bufferedFileWriter.Flush()

	writer := pcapgo.NewWriter(bufferedFileWriter)

	var totalInputSizeBytes int64
	var snaplen uint32 = 262144
	var linkType layers.LinkType
	for _, inputPcapPath := range cmdFlags.Rest.InFiles[1:] {
		inputFile, err := os.Open(inputPcapPath)
		if err != nil {
			if cmdFlags.Verbose {
				fmt.Fprintf(os.Stderr, "%s: %v (skipping this file)\n", inputPcapPath, err)
			}
			continue
		}

		reader, err := pcapgo.NewReader(inputFile)
		if err != nil {
			if cmdFlags.Verbose {
				fmt.Fprintf(os.Stderr, "%s: %v (skipping this file)\n", inputFile.Name(), err)
			}
			continue
		}

		fStat, _ := inputFile.Stat()
		totalInputSizeBytes += fStat.Size()

		reader.SetSnaplen(snaplen)
		if linkType == layers.LinkTypeNull {
			linkType = reader.LinkType()
		} else if linkType != reader.LinkType() {
			panic(fmt.Sprintln(inputFile.Name()+":", "Different LinkTypes:", linkType, reader.LinkType()))
		}

		nextPacket, err := readNext(reader, inputFile, 0, cmdFlags.Verbose)
		if err == nil {
			heap.Push(&minTimeHeap, nextPacket)
		}
	}

	if cmdFlags.Verbose {
		fmt.Fprintf(os.Stderr, "merging %d input files of size %f GiB\n", minTimeHeap.Len(), float64(totalInputSizeBytes)/1024/1024/1024)
		fmt.Fprintf(os.Stderr, "writing to %s\n", outputFile.Name())
	}

	writer.WriteFileHeader(snaplen, linkType)
	for minTimeHeap.Len() > 0 {
		// find the earliest packet and write it to the output file
		earliestPacket := heap.Pop(&minTimeHeap).(packet)
		write(writer, earliestPacket, cmdFlags.Verbose)

		var earliestHeapTime int64
		if minTimeHeap.Len() > 0 {
			earliestHeapTime = minTimeHeap[0].Timestamp
		}
		for {
			// read the next packet from the source of the last written packet
			nextPacket, err := readNext(earliestPacket.Reader, earliestPacket.InputFile, earliestPacket.MinimumLegalTimestamp, cmdFlags.Verbose)
			if err == io.EOF {
				break
			}

			if nextPacket.Timestamp <= earliestHeapTime {
				// this is the earliest packet, write it to the output file
				write(writer, nextPacket, cmdFlags.Verbose)
				continue
			}

			// this is not the earliest packet, push it to the heap for sorting
			heap.Push(&minTimeHeap, nextPacket)
			break
		}
	}
}

func readNext(reader *pcapgo.Reader, inputFile *os.File, minimumLegalTimestamp int64, verbose bool) (packet, error) {
	for {
		data, captureInfo, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				if verbose {
					fmt.Fprintf(os.Stderr, "%s: done\n", inputFile.Name())
				}
				inputFile.Close()

				return packet{}, err
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "%s: %v (skipping this packet)\n", inputFile.Name(), err)
			}
			// skip errors
			continue
		}
		if minimumLegalTimestamp > 0 && captureInfo.Timestamp.UnixNano() < minimumLegalTimestamp {
			if verbose {
				fmt.Fprintf(os.Stderr, "%s: illegal packet timestamp %v (skipping this packet)\n", inputFile.Name(), captureInfo.Timestamp)
			}
			// skip errors
			continue
		}
		if len(data) == 0 {
			if verbose {
				fmt.Fprintf(os.Stderr, "%s: empty data (skipping this packet)\n", inputFile.Name())
			}
			// skip errors
			continue
		}

		if minimumLegalTimestamp == 0 {
			minimumLegalTimestamp = captureInfo.Timestamp.UnixNano()
		}

		return packet{
			Timestamp:             captureInfo.Timestamp.UnixNano(),
			MinimumLegalTimestamp: minimumLegalTimestamp,
			CaptureInfo:           captureInfo,
			Data:                  data,
			Reader:                reader,
			InputFile:             inputFile}, nil
	}
}

func write(writer *pcapgo.Writer, packetToWrite packet, verbose bool) {
	err := writer.WritePacket(packetToWrite.CaptureInfo, packetToWrite.Data)
	if err != nil && verbose {
		fmt.Fprintf(os.Stderr, "write error: %v (skipping this packet)\n", err)
		// skip errors
	}
}

func max(x, y uint32) uint32 {
	if x > y {
		return x
	}
	return y
}
