# Changelog

## v0.8.0 (Jun 12, 2018)

- make as little as possible heap memory allocations
- close input files as soon as we are done with it

## v0.7.6 (Jun 11, 2018)

- read faster with ReadPacketDataNoCopy (currently from github.com/assafmo/gopacket, until the PR is accepted)

## v0.7.5 (Jun 11, 2018)

- pass Packet by pointer
- print infile path on linktype error

## v0.7.4 (Jun 11, 2018)

- new help message
- better parsing of rest args

## v0.7.3 (Jun 10, 2018)

- optimize read if the next packet is from the same source
- benchmarks results as markdown

## v0.7.2 (Jun 10, 2018)

- fix skip packet don't write garbage
- fix usage message
- benchmark.sh don't use tmpfs if less than 6GB of RAM, better logs

## v0.7.1 (Jun 10, 2018)

- fix heap push

## v0.7.0 (Jun 5, 2018)

- fix heap pop & push, use string pointer for pcap path
- pass data by pointer to reduce copy in memory

## v0.6.0 (Jun 4, 2018)

- update usage message
- print version if verbose

## v0.5.0 (Jun 4, 2018)

- skip instead of fail bad pcap files or file read errors
- print (skiping this packet) on errors
- print source pcap on all read errors
- skip errors on first packet

## v0.4.0 (Jun 4, 2018)

- read from source until good packet or EOF
- fix write to stdout instead of file

## v0.3.0 (Jun 4, 2018)

- enable write to file
- better logs
- fix flush write buffer

## v0.2.0 (Jun 1, 2018)

- use buffered writer
- benchmark use tmpfs

## v0.1.0 (May 31, 2018)

- init (works)
