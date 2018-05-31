#!/bin/bash

# get pcaps
wget -nc 'https://download.netresec.com/pcap/maccdc-2012/maccdc2012_00000.pcap.gz' 'https://download.netresec.com/pcap/maccdc-2012/maccdc2012_00001.pcap.gz' 'https://download.netresec.com/pcap/maccdc-2012/maccdc2012_00002.pcap.gz'

# extract pcaps
if [[ ! -f 0.pcap ]]; then 
    zcat maccdc2012_00000.pcap.gz > 0.pcap
fi
if [[ ! -f 1.pcap ]]; then 
    zcat maccdc2012_00001.pcap.gz > 1.pcap
fi
if [[ ! -f 2.pcap ]]; then 
    zcat maccdc2012_00002.pcap.gz > 2.pcap
fi

# mount tmpfs
mkdir -p ./_tmpfs/
sudo mount -t tmpfs -o size=1G tmpfs ./_tmpfs/

# copy pcaps to tmpfs
cp *.pcap ./_tmpfs/

# print versions for joincap, mergecap, tcpslice
echo mergecap version:
mergecap --version

echo tcpslice version:
tcpslice --version

echo joincap version:
joincap --version

# time joincap *pcap > /dev/null
# time mergecap -w - *pcap > /dev/null
# time tcpslice -w - *pcap > /dev/null