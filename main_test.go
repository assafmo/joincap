package main

import (
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

func packetCount(pcapPath string) (uint64, error) {
	inputFile, err := os.Open(pcapPath)
	if err != nil {
		return 0, err
	}
	defer inputFile.Close()

	reader, err := pcapgo.NewReader(inputFile)
	if err != nil {
		return 0, err
	}

	var packetCount uint64
	for {
		_, _, err = reader.ReadPacketData()
		if err == io.EOF {
			return packetCount, nil
		} else if err != nil {
			return 0, err
		}
		packetCount++
	}
}

func isTimeOrdered(pcapPath string) (bool, error) {
	inputFile, err := os.Open(pcapPath)
	if err != nil {
		return false, err
	}
	defer inputFile.Close()

	reader, err := pcapgo.NewReader(inputFile)
	if err != nil {
		return false, err
	}

	var previousTime int64
	for {
		_, capInfo, err := reader.ReadPacketData()
		if err == io.EOF {
			return true, nil
		} else if err != nil {
			return false, err
		}

		currentTime := capInfo.Timestamp.UnixNano()

		if currentTime < previousTime {
			return false, nil
		}

		previousTime = currentTime
	}
}

// TestCount packet count of merged pcap
// should be the sum of the packet counts of the
// input pcaps
func TestCount(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	inputFilePath := "pcap_examples/ok.pcap"

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		inputFilePath, inputFilePath})

	inputPacketCount, err := packetCount(inputFilePath)
	if err != nil {
		t.Fatal(err)
	}
	outputPacketCount, err := packetCount(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if inputPacketCount*2 != outputPacketCount {
		t.Fatalf("inputPacketCount*2 != outputPacketCount (%d != %d)\n", inputPacketCount*2, outputPacketCount)
	}
}

// TestOrder all packets in merged pacap should
// be ordered by time
func TestOrder(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	inputFilePath := "pcap_examples/ok.pcap"

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		inputFilePath, inputFilePath})

	isInputOrdered, err := isTimeOrdered(inputFilePath)
	if err != nil {
		t.Fatal(err)
	}
	if !isInputOrdered {
		t.Fatalf("inputFile %s is not ordered by time\n", inputFilePath)
	}

	isOutputOrdered, err := isTimeOrdered(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !isOutputOrdered {
		t.Fatal("out of order")
	}
}

// TestIgnoreInputFileWithCorruptGlobalHeader merging pcap with
// a corrupt global header should be ignored
func TestIgnoreInputFileWithCorruptGlobalHeader(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		"pcap_examples/bad_global.pcap"})

	outputPacketCount, err := packetCount(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if outputPacketCount != 0 {
		t.Fatalf("outputPacketCount (%d) should be 0", outputPacketCount)
	}
}

// TestIgnorePacketWithCorruptHeader packet with corrupt header should be ignored
func TestIgnorePacketWithCorruptHeader(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	inputFilePath := "pcap_examples/ok.pcap"

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		inputFilePath, "pcap_examples/bad_first_header.pcap"})

	isOutputOrdered, err := isTimeOrdered(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !isOutputOrdered {
		t.Fatal("out of order")
	}

	inputPacketCount, err := packetCount(inputFilePath)
	if err != nil {
		t.Fatal(err)
	}
	outputPacketCount, err := packetCount(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if (inputPacketCount*2)-1 != outputPacketCount {
		t.Fatalf("(inputPacketCount*2)-1 != outputPacketCount (%d != %d)\n", (inputPacketCount*2)-1, outputPacketCount)
	}
}

// TestIgnoreTruncatedPacket truncated packet (EOF) should be ignored
func TestIgnoreTruncatedPacketEOF(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		"pcap_examples/unexpected_eof_on_second_packet.pcap"})

	isOutputOrdered, err := isTimeOrdered(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !isOutputOrdered {
		t.Fatal("out of order")
	}

	outputPacketCount, err := packetCount(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if outputPacketCount != 1 {
		t.Fatalf("outputPacketCount (%d) != 1\n", outputPacketCount)
	}
}

// TestIgnoreEmptyPcap pcap without packets should be ignored
func TestIgnoreEmptyPcap(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	inputFilePath := "pcap_examples/ok.pcap"

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		inputFilePath, "pcap_examples/no_packets.pcap"})

	isOutputOrdered, err := isTimeOrdered(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !isOutputOrdered {
		t.Fatal("out of order")
	}

	inputPacketCount, err := packetCount(inputFilePath)
	if err != nil {
		t.Fatal(err)
	}
	outputPacketCount, err := packetCount(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if inputPacketCount != outputPacketCount {
		t.Fatalf("inputPacketCount != outputPacketCount (%d != %d)\n", inputPacketCount, outputPacketCount)
	}
}
