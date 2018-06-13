#!/bin/bash

BENCHMARK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export TO_MARKDOWN=true

( cd "$BENCHMARK_DIR" ; ./benchmark.sh > /tmp/benchmark 2>&1 )

echo '| | Version | Speed | Time |'
echo '| --- | --- | --- | --- |'
cat /tmp/benchmark | 
    grep -a -A 17 'mergecap:' | 
    awk '/Mergecap \(Wireshark\)/{version=$3} /GiB/{speed=$NF} /real/{time=$2} END{print "| **mergecap** | "version" | "speed" | "time" |" }' | 
    tr -d ']' | tr -cd '[:print:]\n'

cat /tmp/benchmark | 
    grep -a -A 10 'tcpslice:' | 
    awk '/Version/{version=$2} /GiB/{speed=$NF} /real/{time=$2} END{print "| **tcpslice** | "version" | "speed" | "time" |" }' | 
    tr -d ']' | tr -cd '[:print:]\n'

cat /tmp/benchmark | 
    grep -a -A 4 'joincap:' | 
    awk '/joincap v/{version=$2} /GiB/{speed=$NF} /real/{time=$2} END{print "| **joincap** | "version" | "speed" | "time" |" }' | 
    tr -d ']' | tr -cd '[:print:]\n' |
    sed -r 's/v([0-9])/\1/'

echo

echo "- Merging $(ls "$BENCHMARK_DIR"/*pcap | wc -l) files with total size of $(ls -l "$BENCHMARK_DIR"/*pcap | awk '{sum+=$5} END{print sum/1024/1024/1024 "GiB"}')."
echo "- $(grep -a -A 2 Running /tmp/benchmark | tr '\n' ' ')"