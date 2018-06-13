#!/bin/bash

BENCHMARK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# get pcaps
( cd "$BENCHMARK_DIR" ; wget -nc https://download.netresec.com/pcap/maccdc-2012/maccdc2012_0000{0,1,2}.pcap.gz 2> /dev/null )

# extract pcaps
if [[ ! -f "$BENCHMARK_DIR"/0.pcap ]]; then
    echo Extracting 0.pcap
    pv maccdc2012_00000.pcap.gz | zcat > "$BENCHMARK_DIR"/0.pcap
fi
if [[ ! -f "$BENCHMARK_DIR"/1.pcap ]]; then
    echo Extracting 1.pcap
    pv maccdc2012_00001.pcap.gz | zcat > "$BENCHMARK_DIR"/1.pcap
fi
if [[ ! -f "$BENCHMARK_DIR"/2.pcap ]]; then
    echo Extracting 2.pcap
    pv maccdc2012_00002.pcap.gz | zcat > "$BENCHMARK_DIR"/2.pcap
fi

PCAPS_DIR="$BENCHMARK_DIR"
if [[ $(free -m | awk '/Mem/{print $2}') -gt 6000 ]]; then
    echo Mount tmpfs and copy pcaps inside
    # mount tmpfs
    mkdir -p "$BENCHMARK_DIR"/_tmpfs/
    sudo mount -t tmpfs -o size=3G tmpfs "$BENCHMARK_DIR"/_tmpfs/

    # copy pcaps to tmpfs
    cp "$BENCHMARK_DIR"/*.pcap "$BENCHMARK_DIR"/_tmpfs/

    PCAPS_DIR="$BENCHMARK_DIR"/_tmpfs/
fi

if [[ "$TO_MARKDOWN" == "true" ]]; then
    echo mergecap:
    mergecap --version
    time mergecap -w - "$PCAPS_DIR"/*pcap | pv -fab 2>&1 > /dev/null | tail -1

    echo
    echo tcpslice:
    tcpslice --version
    time tcpslice -D -w /dev/stdout "$PCAPS_DIR"/*pcap | pv -fab 2>&1 > /dev/null | tail -1

    echo
    echo joincap:
    joincap --version
    time joincap "$PCAPS_DIR"/*pcap | pv -fab 2>&1 >/dev/null | tail -1
else
    echo mergecap:
    mergecap --version
    time mergecap -w - "$PCAPS_DIR"/*pcap | pv -f > /dev/null

    echo
    echo tcpslice:
    tcpslice --version
    time tcpslice -D -w /dev/stdout "$PCAPS_DIR"/*pcap | pv -f > /dev/null

    echo
    echo joincap:
    joincap --version
    time joincap "$PCAPS_DIR"/*pcap | pv -f >/dev/null
fi

if [[ $(free -m | awk '/Mem/{print $2}') -gt 6000 ]]; then
    sleep 3
    sudo umount "$BENCHMARK_DIR"/_tmpfs/
    rm -rf "$BENCHMARK_DIR"/_tmpfs/
fi