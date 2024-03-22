// Merge multiple pcap files together, gracefully.
//
//	Usage:
//	  joincap [OPTIONS] InFiles...
//
//	Application Options:
//	  -v, --verbose  Explain when skipping packets or entire input files
//	  -V, --version  Print the version and exit
//	  -w=            Sets the output filename. If the name is '-', stdout will be used (default: -)
//
//	  -c=            A positive integer argument for limiting the number of packets (default: 9223372036854775807)
//	 Help Options:
//	   -h, --help     Show this help message
package main

import (
	"bufio"
	"container/heap"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"time"

	"github.com/assafmo/joincap/minheap"
	humanize "github.com/dustin/go-humanize"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	flags "github.com/jessevdk/go-flags"
)

const version = "0.11.0"
const maxSnaplen uint32 = 262144

// previousTimestamp is the timestamp of the previous packet popped from the heap.
// It helps us find bad/corrupted packets with weird timestamps.
var previousTimestamp int64

func main() {
	err := joincap(os.Args)
	if err != nil {
		log.Println(err)
	}
}

func joincap(args []string) error {
	packetCounter := 0
	packetLimitReached := false
	log.SetOutput(os.Stderr)

	var cmdFlags struct {
		Verbose        bool   `short:"v" long:"verbose" description:"Explain when skipping packets or input files"`
		Version        bool   `short:"V" long:"version" description:"Print the version and exit"`
		Precision      string `short:"p" choice:"micros" choice:"nanos" default:"micros" description:"Sets timestamp precision"`
		OutputFilePath string `short:"w" default:"-" description:"Sets the output filename. If the name is '-', stdout will be used"`
		Count          int    `short:"c" description:"A positive integer argument for limiting the number of packets"`
		Rest           struct {
			InFiles []string
		} `positional-args:"yes" required:"yes"`
	}
	cmdFlags.Count = math.MaxInt
	_, err := flags.ParseArgs(&cmdFlags, args)

	if err != nil {
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			// If -h flag, help is printed by the library on exit
			printVersionSloganLink()
			return nil
		}
		return fmt.Errorf("cmd flags error: %v", err)
	}

	// If -V flag, print version and exit
	if cmdFlags.Version {
		printVersionSloganLink()
		return nil
	}

	inputFilePaths := cmdFlags.Rest.InFiles[1:]

	if len(inputFilePaths) == 0 {
		flags.NewParser(&cmdFlags, 0).WriteHelp(os.Stdout)
		printVersionSloganLink()
		return nil
	}

	if cmdFlags.Verbose {
		log.Printf("joincap v%s - https://github.com/assafmo/joincap\n", version)
	}

	if cmdFlags.Count <= 0 || cmdFlags.Count == math.MaxInt {
		if cmdFlags.Verbose {
			log.Printf("Packet limit is either less than or equal to zero or not specified. Default limit will be applied on the number of packets.")
		}
		cmdFlags.Count = math.MaxInt
	} else {
		if cmdFlags.Verbose {
			log.Printf("Limiting number of packets to %d packets\n", cmdFlags.Count)
		}
	}

	// Init a minimum heap by packet timestamp
	minTimeHeap := minheap.PacketHeap{}
	heap.Init(&minTimeHeap)

	linkType, err := initHeapWithInputFiles(inputFilePaths, &minTimeHeap, cmdFlags.Verbose)
	if err != nil {
		return fmt.Errorf("cannot initialize merge: %v", err)
	}

	// Init the output file
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

	var writer *pcapgo.Writer

	if cmdFlags.Precision == "nanos" {
		writer = pcapgo.NewWriterNanos(bufferedFileWriter)
	} else {
		writer = pcapgo.NewWriter(bufferedFileWriter)
	}
	writer.WriteFileHeader(maxSnaplen, linkType)

	// Main loop
	for minTimeHeap.Len() > 0 {
		// Find the earliest packet and write it to the output file
		if packetLimitReached {
			break
		}
		earliestPacket := heap.Pop(&minTimeHeap).(minheap.Packet)
		write(writer, earliestPacket, cmdFlags.Verbose)
		packetCounter++
		if packetCounter == cmdFlags.Count {
			packetLimitReached = true
		}

		var earliestHeapTime int64
		if minTimeHeap.Len() > 0 {
			earliestHeapTime = minTimeHeap[0].Timestamp
		}
		for {
			if packetLimitReached {
				break
			}
			// Read the next packet from the source of the last written packet
			nextPacket, err := readNext(
				earliestPacket.Reader,
				earliestPacket.InputFile,
				cmdFlags.Verbose,
				false)
			if err == io.EOF {
				// Done with this source
				break
			}

			if nextPacket.Timestamp <= earliestHeapTime {
				// This is the earliest packet, write it to the output file
				// (Skip pushing it to the heap. This is much faster)
				write(writer, nextPacket, cmdFlags.Verbose)
				packetCounter++
				if packetCounter == cmdFlags.Count {
					packetLimitReached = true
				}
				continue
			}

			// This is not the earliest packet, push it to the heap for sorting
			heap.Push(&minTimeHeap, nextPacket)
			break
		}
	}
	return nil
}

func printVersionSloganLink() {
	fmt.Printf("joincap v%s\n\n", version)
	fmt.Println("Merge multiple pcap files together, gracefully.")
	fmt.Println("For more info visit https://github.com/assafmo/joincap")
}

// initHeapWithInputFiles inits minTimeHeap with one packet from each source file.
// It also returns the output LinkType, which is decided by the LinkTypes of all of the
// input files.
func initHeapWithInputFiles(inputFilePaths []string, minTimeHeap *minheap.PacketHeap, verbose bool) (layers.LinkType, error) {
	var totalInputSizeBytes int64
	var linkType layers.LinkType

	for _, inputPcapPath := range inputFilePaths {
		// Read the first packet and push it to the heap
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
			// Init
			linkType = reader.LinkType()
		} else if linkType != reader.LinkType() {
			// Conflicting input LinkTypes. Use default type of Ethernet.
			linkType = layers.LinkTypeEthernet
		}

		nextPacket, err := readNext(reader, inputFile, verbose, true)
		if err != nil {
			if verbose {
				log.Printf("%s: %v before first packet (skipping this file)\n", inputFile.Name(), err)
			}
			continue
		}

		heap.Push(minTimeHeap, nextPacket)

		// Init previousTimestamp
		if previousTimestamp == 0 {
			previousTimestamp = nextPacket.Timestamp
		} else if nextPacket.Timestamp < previousTimestamp {
			previousTimestamp = nextPacket.Timestamp
		}
	}

	if verbose {
		size := humanize.IBytes(uint64(totalInputSizeBytes))
		log.Printf("merging %d input files of size %s\n", minTimeHeap.Len(), size)
	}

	return linkType, nil
}

func readNext(reader *pcapgo.Reader, inputFile *os.File, verbose bool, isInit bool) (minheap.Packet, error) {
	for {
		data, captureInfo, err := reader.ZeroCopyReadPacketData()
		if err != nil {
			if err == io.EOF {
				// Done with this source

				if verbose {
					log.Printf("%s: done (closing)\n", inputFile.Name())
				}
				inputFile.Close()

				return minheap.Packet{}, io.EOF
			}
			if verbose {
				log.Printf("%s: %v (skipping this packet)\n", inputFile.Name(), err)
			}
			// Skip errors
			continue
		}

		timestamp := captureInfo.Timestamp.UnixNano()
		oneHour := int64(time.Nanosecond * time.Hour)

		if !isInit && timestamp+oneHour < previousTimestamp {
			if verbose {
				log.Printf("%s: illegal packet timestamp %v - more than an hour before the previous packet's timestamp %v (skipping this packet)\n",
					inputFile.Name(),
					captureInfo.Timestamp.UTC(),
					time.Unix(0, previousTimestamp).UTC())
			}
			// Skip errors
			continue
		}
		if len(data) == 0 {
			if verbose {
				log.Printf("%s: empty data (skipping this packet)\n", inputFile.Name())
			}
			// Skip errors
			continue
		}

		return minheap.Packet{
			Timestamp:   timestamp,
			CaptureInfo: captureInfo,
			Data:        data,
			Reader:      reader,
			InputFile:   inputFile,
		}, nil
	}
}

func write(writer *pcapgo.Writer, packetToWrite minheap.Packet, verbose bool) {
	err := writer.WritePacket(packetToWrite.CaptureInfo, packetToWrite.Data)
	if err != nil && verbose { // Skip errors
		log.Printf("write error: %v (skipping this packet)\n", err)
	}

	previousTimestamp = packetToWrite.Timestamp
}
