#!/bin/bash

BENCHMARK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

( cd "$BENCHMARK_DIR" ; ./benchmark.sh > /tmp/benchmark 2>&1 )

echo '| | Version | Speed | Time |'
echo '| --- | --- | --- | --- |'
cat /tmp/benchmark | grep -A 17 'mergecap:' | awk '/Mergecap \(Wireshark\)/{version=$3} /<=>/{speed=$4} /real/{time=$2} END{print "| **mergecap** | "version" | "speed" | "time" |" }' | tr -d ]

cat /tmp/benchmark | grep -A 10 'tcpslice:' | awk '/Version/{version=$2} /<=>/{speed=$4} /real/{time=$2} END{print "| **tcpslice** | "version" | "speed" | "time" |" }' | tr -d ]

cat /tmp/benchmark | grep -A 4 'joincap:' | awk '/joincap v/{version=$2} /<=>/{speed=$4} /real/{time=$2} END{print "| **joincap** | "version" | "speed" | "time" |" }' | tr -d ']' | sed -r 's/v([0-9])/\1/'

echo

echo - Merging $(ls "$BENCHMARK_DIR"/*pcap | wc -l) files with total size of $(ls -l "$BENCHMARK_DIR"/*pcap | awk '{sum+=$5} END{print sum/1024/1024/1024 "GiB"}').
echo "- $(grep -A 2 Running /tmp/benchmark | tr -d '\n')"