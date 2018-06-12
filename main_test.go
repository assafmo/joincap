package main

import (
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

// TestPacketCount packet count of merged pcap
// should be the sum of the packet counts of the
// input pcaps
func TestPacketCount(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	inputFilePath := "examples/ok.pcap"

	joincap([]string{"joincap", "-w", outputFile.Name(), inputFilePath, inputFilePath})

	inputCount, err := countPackets(inputFilePath)
	if err != nil {
		t.Fatal(err)
	}
	outputCount, err := countPackets(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if inputCount*2 != outputCount {
		t.Fatalf("inputCount*2 != outputCount (%d != %d)\n", inputCount*2, outputCount)
	}
}

func countPackets(pcapPath string) (packetCount uint64, err error) {
	inputFile, err := os.Open(pcapPath)
	if err != nil {
		return
	}
	defer inputFile.Close()

	reader, err := pcapgo.NewReader(inputFile)
	if err != nil {
		return
	}

	for {
		_, _, err = reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				err = nil
				break
			} else {
				return
			}
		}
		packetCount++
	}

	return
}
