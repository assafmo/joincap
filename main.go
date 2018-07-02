package main

import (
	"bufio"
	"container/heap"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	flags "github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
)

const version = "0.8.7"
const maxSnaplen = 262144

func main() {
	err := joincap(os.Args)
	if err != nil {
		log.Println(err)
	}
}

func joincap(args []string) error {
	log.SetOutput(os.Stderr)

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
			// if -h flag, help is printed by the library on exit
			return nil
		}
		return errors.Wrap(err, "cmd flags error")
	}

	// if -V flag, print version and exit
	if cmdFlags.Version {
		fmt.Printf("joincap v%s\n", version)
		return nil
	}

	if cmdFlags.Verbose {
		log.Printf("joincap v%s\n", version)
	}

	minTimeHeap := packetHeap{}
	heap.Init(&minTimeHeap)

	outputFile := os.Stdout
	if cmdFlags.OutputFilePath != "-" {
		outputFile, err = os.Create(cmdFlags.OutputFilePath)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("cannot open %s for writing", cmdFlags.OutputFilePath))
		}
		defer outputFile.Close()
	}
	bufferedFileWriter := bufio.NewWriter(outputFile)
	defer bufferedFileWriter.Flush()

	writer := pcapgo.NewWriter(bufferedFileWriter)

	var totalInputSizeBytes int64
	var linkType layers.LinkType
	for _, inputPcapPath := range cmdFlags.Rest.InFiles[1:] {
		inputFile, err := os.Open(inputPcapPath)
		if err != nil {
			if cmdFlags.Verbose {
				log.Printf("%s: %v (skipping this file)\n", inputPcapPath, err)
			}
			continue
		}

		reader, err := pcapgo.NewReader(inputFile)
		if err != nil {
			if cmdFlags.Verbose {
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
			return fmt.Errorf("%s: different linktypes: %v %v",
				inputFile.Name(),
				linkType,
				reader.LinkType())
		}

		nextPacket, err := readNext(reader, inputFile, 0, cmdFlags.Verbose)
		if err == nil {
			heap.Push(&minTimeHeap, nextPacket)
		} else {
			log.Printf("%s: %v before first packet (skipping this file)\n", inputFile.Name(), err)
		}
	}

	if cmdFlags.Verbose {
		log.Printf("merging %d input files of size %f GiB\n",
			minTimeHeap.Len(),
			float64(totalInputSizeBytes)/1024/1024/1024)
		log.Printf("writing to %s\n", outputFile.Name())
	}

	writer.WriteFileHeader(maxSnaplen, linkType)
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
			nextPacket, err := readNext(
				earliestPacket.Reader,
				earliestPacket.InputFile,
				earliestPacket.MinimumLegalTimestamp,
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

func readNext(reader *pcapgo.Reader, inputFile *os.File, minimumLegalTimestamp int64, verbose bool) (packet, error) {
	for {
		data, captureInfo, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				if verbose {
					log.Printf("%s: done (closing)\n", inputFile.Name())
				}
				inputFile.Close()

				return packet{}, io.EOF
			}
			if verbose {
				log.Printf("%s: %v (skipping this packet)\n", inputFile.Name(), err)
			}
			// skip errors
			continue
		}
		if minimumLegalTimestamp > 0 &&
			captureInfo.Timestamp.UnixNano() < minimumLegalTimestamp {
			if verbose {
				log.Printf("%s: illegal packet timestamp %v (skipping this packet)\n", inputFile.Name(), captureInfo.Timestamp)
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

		if minimumLegalTimestamp == 0 {
			minimumLegalTimestamp = captureInfo.Timestamp.UnixNano()
		}

		return packet{
			Timestamp:             captureInfo.Timestamp.UnixNano(),
			MinimumLegalTimestamp: minimumLegalTimestamp,
			CaptureInfo:           captureInfo,
			Data:                  data,
			Reader:                reader,
			InputFile:             inputFile,
		}, nil
	}
}

func write(writer *pcapgo.Writer, packetToWrite packet, verbose bool) {
	err := writer.WritePacket(packetToWrite.CaptureInfo, packetToWrite.Data)
	if err != nil && verbose { // skip errors
		log.Printf("write error: %v (skipping this packet)\n", err)
	}
}
