#!/bin/bash
set -x

BENCHMARK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# get pcaps
( cd "$BENCHMARK_DIR" ; wget -nc https://download.netresec.com/pcap/maccdc-2012/maccdc2012_0000{0,1,2}.pcap.gz )

# extract pcaps
if [[ ! -f "$BENCHMARK_DIR"/0.pcap ]]; then 
    zcat maccdc2012_00000.pcap.gz > "$BENCHMARK_DIR"/0.pcap
fi
if [[ ! -f "$BENCHMARK_DIR"/1.pcap ]]; then 
    zcat maccdc2012_00001.pcap.gz > "$BENCHMARK_DIR"/1.pcap
fi
if [[ ! -f "$BENCHMARK_DIR"/2.pcap ]]; then 
    zcat maccdc2012_00002.pcap.gz > "$BENCHMARK_DIR"/2.pcap
fi

# mount tmpfs
mkdir -p "$BENCHMARK_DIR"/_tmpfs/
sudo mount -t tmpfs -o size=3G tmpfs "$BENCHMARK_DIR"/_tmpfs/

# copy pcaps to tmpfs
cp "$BENCHMARK_DIR"/*.pcap "$BENCHMARK_DIR"/_tmpfs/

# print versions for joincap, mergecap, tcpslice
echo mergecap:
mergecap --version
time mergecap -w - "$BENCHMARK_DIR"/_tmpfs/*pcap | pv > /dev/null

echo
echo tcpslice:
tcpslice --version
time tcpslice -w /dev/stdout "$BENCHMARK_DIR"/_tmpfs/*pcap | pv > /dev/null

echo
echo joincap:
joincap --version
time joincap "$BENCHMARK_DIR"/_tmpfs/*pcap | pv > /dev/null

sleep 3
sudo umount -f "$BENCHMARK_DIR"/_tmpfs/
rm -rf "$BENCHMARK_DIR"/_tmpfs/