# Changelog

## v0.11.1 (May 4, 2025)

- fix wildcard expansion on windows

## v0.11.0 (Nov 14, 2024)

- add flag -p for timestamp precision in nanoseconds

## v0.10.2 (Apr 18, 2020)

- use ZeroCopyReadPacketData which is much faster than ReadPacketData

## v0.10.1 (Feb 19, 2019)

- print help messege if no input files were given

## v0.10.0 (Oct 31, 2018)

- allow mixing of different input linktypes

## v0.9.2 (Oct 31, 2018)

- fix bug introduced in v0.9.0 - input file passing order can make previousTimestamp be initialized wrong and reject later input files
- fix a log print that should only be printed in verbose mode

## v0.9.1 (Oct 29, 2018)

- fix initialization of previousTimestamp (timestamp corruption check)

## v0.9.0 (Oct 28, 2018)

- detect bad packets if an hour earlier than previous packet

## v0.8.9 (Oct 25, 2018)

- better wrapping of error messages

## v0.8.8 (Oct 24, 2018)

- humanize byte size printing in verbose mode (TiB, GiB, MiB, KiB)
- minheap tests

## v0.8.7 (Jun 29, 2018)

- better error handling
- more tests coverage

## v0.8.6 (Jun 27, 2018)

- use the golang logger (logs with datetime)

## v0.8.5 (Jun 25, 2018)

- per input file, set minimum legal timestamp as the first packet's time
- don't allow to read packets with illegal timestamps (probably faulty packet header)

## v0.8.4 (Jun 25, 2018)

- use our own snaplen to avoid small snaplens by bad pcap writers

## v0.8.3 (Jun 12, 2018)

- cmdFlags no longer global
- default snaplen

## v0.8.2 (Jun 12, 2018)

- fix use inputFile after error on open

## v0.8.1 (Jun 12, 2018)

- skip empty packets (probably bad packet header)

## v0.8.0 (Jun 12, 2018)

- make as little as possible heap memory allocations
- close each input file as soon as we are done with it

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
