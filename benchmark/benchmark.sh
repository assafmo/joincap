#!/bin/bash

# get pcaps
wget -nc https://download.netresec.com/pcap/maccdc-2012/maccdc2012_0000{0,1,2}.pcap.gz

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
sudo mount -t tmpfs -o size=4G tmpfs ./_tmpfs/

# copy pcaps to tmpfs
cp *.pcap ./_tmpfs/

# print versions for joincap, mergecap, tcpslice
echo mergecap:
mergecap --version
time mergecap -w - ./_tmpfs/*pcap | pv > /dev/null

echo
echo tcpslice:
tcpslice --version
time tcpslice -w /dev/stdout ./_tmpfs/*pcap | pv > /dev/null

echo
echo joincap:
joincap --version
time joincap ./_tmpfs/*pcap | pv > /dev/null


sudo umount _tmpfs
rm -rf _tmpfs