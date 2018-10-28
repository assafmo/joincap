// Merge multiple pcap files together, gracefully.
//
//  Usage:
//    joincap [OPTIONS] InFiles...
//
//  Application Options:
//    -v, --verbose  Explain when skipping packets or entire input files
//    -V, --version  Print the version and exit
//    -w=            Sets the output filename. If the name is '-', stdout will be used (default: -)
//
//  Help Options:
//    -h, --help     Show this help message
package main

import (
	"bufio"
	"container/heap"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/assafmo/joincap/minheap"
	humanize "github.com/dustin/go-humanize"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	flags "github.com/jessevdk/go-flags"
)

const version = "0.9.0"
const maxSnaplen uint32 = 262144

var priorTimestamp int64

func main() {
	err := joincap(os.Args)
	if err != nil {
		log.Println(err)
	}
}

func joincap(args []string) error {
	log.SetOutput(os.Stderr)

	var cmdFlags struct {
		Verbose        bool   `short:"v" long:"verbose" description:"Explain when skipping packets or input files"`
		Version        bool   `short:"V" long:"version" description:"Print the version and exit"`
		OutputFilePath string `short:"w" default:"-" description:"Sets the output filename. If the name is '-', stdout will be used"`
		Rest           struct {
			InFiles []string
		} `positional-args:"yes" required:"yes"`
	}

	_, err := flags.ParseArgs(&cmdFlags, args)

	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			// if -h flag, help is printed by the library on exit
			return nil
		}
		return fmt.Errorf("cmd flags error: %v", err)
	}

	// if -V flag, print version and exit
	if cmdFlags.Version {
		fmt.Printf("joincap v%s\n", version)
		return nil
	}

	if cmdFlags.Verbose {
		log.Printf("joincap v%s\n", version)
	}

	minTimeHeap := minheap.PacketHeap{}
	heap.Init(&minTimeHeap)
	linkType, err := initHeapWithInputFiles(cmdFlags.Rest.InFiles[1:], &minTimeHeap, cmdFlags.Verbose)
	if err != nil {
		return fmt.Errorf("cannot initiate merge: %v", err)
	}

	outputFile := os.Stdout
	if cmdFlags.OutputFilePath != "-" {
		outputFile, err = os.Create(cmdFlags.OutputFilePath)
		if err != nil {
			return fmt.Errorf("cannot open %s for writing: %v", cmdFlags.OutputFilePath, err)
		}
		defer outputFile.Close()
	}
	bufferedFileWriter := bufio.NewWriter(outputFile)
	defer bufferedFileWriter.Flush()

	if cmdFlags.Verbose {
		log.Printf("writing to %s\n", outputFile.Name())
	}

	writer := pcapgo.NewWriter(bufferedFileWriter)
	writer.WriteFileHeader(maxSnaplen, linkType)
	for minTimeHeap.Len() > 0 {
		// find the earliest packet and write it to the output file
		earliestPacket := heap.Pop(&minTimeHeap).(minheap.Packet)
		write(writer, earliestPacket, cmdFlags.Verbose)

		var earliestHeapTime int64
		if minTimeHeap.Len() > 0 {
			earliestHeapTime = minTimeHeap[0].Timestamp
		}
		for {
			// read the next packet from the source of the last written packet
			nextPacket, err := readNext(
				earliestPacket.Reader,
				earliestPacket.InputFile,
				cmdFlags.Verbose)
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
	return nil
}

func initHeapWithInputFiles(inputFilePaths []string, minTimeHeap *minheap.PacketHeap, verbose bool) (layers.LinkType, error) {
	var totalInputSizeBytes int64
	var linkType layers.LinkType
	for _, inputPcapPath := range inputFilePaths {
		inputFile, err := os.Open(inputPcapPath)
		if err != nil {
			if verbose {
				log.Printf("%s: %v (skipping this file)\n", inputPcapPath, err)
			}
			continue
		}

		reader, err := pcapgo.NewReader(inputFile)
		if err != nil {
			if verbose {
				log.Printf("%s: %v (skipping this file)\n", inputFile.Name(), err)
			}
			continue
		}

		fStat, _ := inputFile.Stat()
		totalInputSizeBytes += fStat.Size()

		reader.SetSnaplen(maxSnaplen)
		if linkType == layers.LinkTypeNull {
			linkType = reader.LinkType()
		} else if linkType != reader.LinkType() {
			return layers.LinkTypeNull,
				fmt.Errorf(
					"%s: different linktypes: %v %v",
					inputFile.Name(),
					linkType,
					reader.LinkType(),
				)
		}

		nextPacket, err := readNext(reader, inputFile, verbose)
		if err == nil {
			heap.Push(minTimeHeap, nextPacket)
			if nextPacket.Timestamp < priorTimestamp {
				priorTimestamp = nextPacket.Timestamp
			}
		} else {
			log.Printf("%s: %v before first packet (skipping this file)\n", inputFile.Name(), err)
		}
	}

	if verbose {
		log.Printf("merging %d input files of size %s\n",
			minTimeHeap.Len(),
			humanize.IBytes(uint64(totalInputSizeBytes)))
	}

	return linkType, nil
}

func readNext(reader *pcapgo.Reader, inputFile *os.File, verbose bool) (minheap.Packet, error) {
	for {
		data, captureInfo, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				if verbose {
					log.Printf("%s: done (closing)\n", inputFile.Name())
				}
				inputFile.Close()

				return minheap.Packet{}, io.EOF
			}
			if verbose {
				log.Printf("%s: %v (skipping this packet)\n", inputFile.Name(), err)
			}
			// skip errors
			continue
		}
		if captureInfo.Timestamp.UnixNano()+int64(time.Nanosecond*time.Hour) < priorTimestamp {
			if verbose {
				log.Printf("%s: illegal packet timestamp %v - more than an hour before the prior packet's timestamp %v (skipping this packet)\n",
					inputFile.Name(),
					captureInfo.Timestamp,
					time.Unix(0, priorTimestamp).UTC())
			}
			// skip errors
			continue
		}
		if len(data) == 0 {
			if verbose {
				log.Printf("%s: empty data (skipping this packet)\n", inputFile.Name())
			}
			// skip errors
			continue
		}

		return minheap.Packet{
			Timestamp:   captureInfo.Timestamp.UnixNano(),
			CaptureInfo: captureInfo,
			Data:        data,
			Reader:      reader,
			InputFile:   inputFile,
		}, nil
	}
}

func write(writer *pcapgo.Writer, packetToWrite minheap.Packet, verbose bool) {
	err := writer.WritePacket(packetToWrite.CaptureInfo, packetToWrite.Data)
	if err != nil && verbose { // skip errors
		log.Printf("write error: %v (skipping this packet)\n", err)
	}

	priorTimestamp = packetToWrite.Timestamp
}
