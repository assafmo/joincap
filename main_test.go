package main

import (
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

const okPcap = "pcap_examples/ok.pcap"

func packetCount(t *testing.T, pcapPath string) uint64 {
	inputFile, err := os.Open(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer inputFile.Close()

	reader, err := pcapgo.NewReader(inputFile)
	if err != nil {
		t.Fatal(err)
	}

	var packetCount uint64
	for {
		_, _, err = reader.ReadPacketData()
		if err == io.EOF {
			return packetCount
		} else if err != nil {
			t.Fatal(err)
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

func testIsOrdered(t *testing.T, pcapPath string) {
	isOutputOrdered, err := isTimeOrdered(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	if !isOutputOrdered {
		t.Fatal("out of order")
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

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		okPcap, okPcap})

	if packetCount(t, outputFile.Name()) != packetCount(t, okPcap)*2 {
		t.FailNow()
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

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		okPcap, okPcap})

	testIsOrdered(t, okPcap)
	testIsOrdered(t, outputFile.Name())
}

// TestIgnoreInputFileCorruptGlobalHeader merging pcap with
// a corrupt global header should be ignored
func TestIgnoreInputFileCorruptGlobalHeader(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		"pcap_examples/bad_global.pcap"})

	if packetCount(t, outputFile.Name()) != 0 {
		t.FailNow()
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

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		okPcap, "pcap_examples/bad_first_header.pcap"})

	testIsOrdered(t, outputFile.Name())

	// bad_first_header.pcap is ok.pcap with its first packet header ruined
	if (packetCount(t, okPcap)*2)-1 != packetCount(t, outputFile.Name()) {
		t.FailNow()
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

	testIsOrdered(t, outputFile.Name())

	if packetCount(t, outputFile.Name()) != 1 {
		t.FailNow()
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

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		okPcap, "pcap_examples/no_packets.pcap"})

	testIsOrdered(t, outputFile.Name())

	if packetCount(t, outputFile.Name()) != packetCount(t, okPcap) {
		t.FailNow()
	}
}

// TestIgnoreInputFileTruncatedGlobalHeader pcap without full global header (< 24 bytes) should be ignored
func TestIgnoreInputFileTruncatedGlobalHeader(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		okPcap, "pcap_examples/partial_global_header.pcap"})

	testIsOrdered(t, outputFile.Name())

	if packetCount(t, outputFile.Name()) != packetCount(t, okPcap) {
		t.FailNow()
	}
}

// TestIgnoreInputFileTruncatedFirstPacketHeader pcap without full first packet header (24 < size < 40 bytes) should be ignored
func TestIgnoreInputFileTruncatedFirstPacketHeader(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		"pcap_examples/partial_first_header.pcap", okPcap})

	testIsOrdered(t, outputFile.Name())

	if packetCount(t, outputFile.Name()) != packetCount(t, okPcap) {
		t.FailNow()
	}
}

// TestIgnoreInputFileDoesntExists non existing input files should be ignored
func TestIgnoreInputFileDoesNotExists(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		"/nothing/here", okPcap, "or_here"})

	testIsOrdered(t, outputFile.Name())

	if packetCount(t, outputFile.Name()) != packetCount(t, okPcap) {
		t.FailNow()
	}
}

// TestIgnoreInputFileIsDirectory directory as input file should be ignored
func TestIgnoreInputFileIsDirectory(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		"pcap_examples", okPcap})

	testIsOrdered(t, outputFile.Name())

	if packetCount(t, outputFile.Name()) != packetCount(t, okPcap) {
		t.FailNow()
	}
}

// TestIgnoreGarbageEndingOfPcap garbage at end of pcap should be ignored (this kills tcpslice)
func TestIgnoreGarbageEndingOfPcap(t *testing.T) {
	outputFile, err := ioutil.TempFile("", "joincap_output_")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	joincap([]string{"joincap",
		"-w", outputFile.Name(),
		"pcap_examples/bad_end.pcap", okPcap})

	testIsOrdered(t, outputFile.Name())

	// bad_end.pcap is ok.pcap with the last packet header ruined and garbage appended to it
	if packetCount(t, outputFile.Name()) != (packetCount(t, okPcap)*2)-1 {
		t.FailNow()
	}
}
