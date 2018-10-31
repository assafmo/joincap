# Changelog

## v0.9.2 (Oct 31, 2018)
- TestInputFilePassingOrderDoesNotMatter
- test mix little and big endian input files
- fix bug intruduced in v0.9.0
- in heap init, input file load order can make priorTimestamp be initialized wrong and reject later input files
- fix a log print that should  only be printed in verbose mode

## v0.9.1 (Oct 29, 2018)
- restore old test with 1970 date in the middle
- ignore *pprof*
- fix priorTimestamp init

## v0.9.0 (Oct 28, 2018)
- detect bad timestamp if more than an hour earlier than previous packet
- fix small snaplen test, add big & normal snaplen tests
- maxSnaplen in uint32
- fix typos in comments
- set stderr to nil while testing so verbose mode won't pollute the test output
- remove circleci temple notes
- remove gh issue template
- readme snap install no sudo
- update benchmarks
- changelog semantics
- chagelog v0.8.9

## v0.8.9 (Oct 25, 2018)
- better wrap error messages

## v0.8.8 (Oct 24, 2018)
- humanize byte size printing
- clean so more snap stuff
- do_release.sh clean more snap stuff
- ignore more snap stuff, changlog semantics
- changelog v0.8.8
- readme install & use before why
- godoc
- godoc
- Installation Options
- snap cleanup
- reademe snap
- better release script
- snap realease script
- snap package
- simple benchmark to profile memory
- fix basic usage cli name
- installation link to go
- release script to release binaries on github
- clarify heap comment
- initHeapWithInputFiles initializes the heap with the input files
- test coverage for minheap
- minheap tests
- seperate the heap into its own package
- refactor help message
- remove pprof comments

## v0.8.7 (Jun 29, 2018)
- ignore test coverage files
- fix TestExitOnDifferentLinkTypes changed error message
- slightly better error handling
- test cannot merge different linktypes
- test writing to file in non existing directory
- tests exit on unknown cli flag
- TestPrintHelp
- return errors to main (easier to test failing states)
- TestPrintVersion
- test using --verbose, remove dead code
- no need to test twice
- test coverage badge
- fix again?
- fix coveralls command
- try coveralls.io

## v0.8.6 (Jun 27, 2018)
- use the golang logger
- return to use google/gopacket after google/gopacket#474

## v0.8.5 (Jun 25, 2018)
- comments for TestIgnoreTooSmallSnaplen & TestIgnorePacketsWithTimeEarlierThanFirst
- TestIgnorePacketsWithTimeEarlierThanFirst packets with timestamp smaller than the first packet should be ignored
- TestIgnoreToSmallSnaplen snaplen should be ignored and we use our own snaplen (v0.8.4)
- per input file set minimum allowed time as the first packet's time

## v0.8.4 (Jun 25, 2018)
- use my own snaplen to avoid small snaplens by bad pcap writers
- Update bug_report.md
- Update issue templates
- test the helper function isTimeOrdered
- Merge branch 'master' of github.com:assafmo/joincap
- test the helper function packetCount
- tcpslice -D
- benchmark live print if not outputing markdown
- benchmark tcpslice with -D (faster)
- headers semantics
- reorder results table
- reorder headlines, how to reproduce the errors
- rename make_changelog.sh -> CHANGELOG.sh
- rename make_changelog.sh -> CHANGELOG.sh
- typo
- Seperate error handling into two tables (results and outputs)
- newlines in table
- fix unexpectd EOF results for mergecap and tcpslice
- joincap first in error handling table
- fix benchmark.sh prints non ascii chars
- remove version from usage
- refactor structs names
- pcap_examples/ok.pcap.gz
- test gzipped pcap should merge just fine (this kills tcpslice)
- test garbage at end of pcap should be ignored (this kills tcpslice)
- test directory as input file should be ignored
- test  non existing input files should be ignored
- refactor tests
- circleci print go version
- circleci/golang:latest
- test pcap without full first packet header (24 < size < 40 bytes) should be ignored
- test pcap without full global header (< 24 bytes) should be ignored
- pcap without packets should be ignored
- truncated packet (EOF) should be ignored

## v0.8.3 (Jun 12, 2018)
- test packet with corrupt header should be ignored
- test ignore input with corrupt global header
- cmdFlags no longer global
- set default snaplen
- circleci badge
- fix circleci config
- .circleci test on push
- rename dir examples ->pcap_examples
- test output ordered by time
- test packet count
- go report badge
- fix example in Error handling (partial_first_header.pcap)

## v0.8.2 (Jun 12, 2018)
- fix use inputFile after error on open
- changelog v0.8.1

## v0.8.1 (Jun 12, 2018)
- skip empty packets (probably bad packet header)
- Println -> Printf
- refactor comments, vars names
- changelog grammer
- benchmarks markdown spacing

## v0.8.0 (Jun 12, 2018)
- make as little as possible heap memory allocations
- close file as soon as we are done with it
- benchmarks v0.7.6
- make_changelog.sh spacing
- clean changelog
- changelog.sh -> make_changelog.sh
- changelog file & script

## v0.7.6 (Jun 11, 2018)
- read faster with ReadPacketDataNoCopy
- (currently from assafmo/gopacket/pcapgo, until the PR is accepted)

## v0.7.5 (Jun 11, 2018)
- pass Packet by pointer
- rename some more vars
- rename vars
- reorder comments
- print infile path if on linktype error
- comment explain why -h and -V prints to stdout and the rest to stderr

## v0.7.4 (Jun 11, 2018)
- new help message
- better parsing of rest args
- refactor conditions, rename vars
- comment on read optimization

## v0.7.3 (Jun 10, 2018)
- optimize read if the next packet is from the same source
- benchmarks first column in bold
- benchmark markdown pcap size
- benchmarks results as markdown
- update benchmarks
- benchmark mkdir -p

## v0.7.2 (Jun 10, 2018)
- fix skip packet don't write garbage
- fix usage
- benchmark.sh don't use tmpfs if less than 6GB of RAM, better logs

## v0.7.1 (Jun 10, 2018)
- fix heap push
- readers slice unused
- refactor main loop condition
- benchmarks tldr rephrase
- update benchmarks

## v0.7.0 (Jun 5, 2018)
- fix heap pop & push, use string pointer for pcap path
- benchmark independent from working directory
- log "skipping this file"
- typo skiping -> skipping
- TLDR benchmarks
- panic instead of log
- gracefully
- refactor rename h to minimumHeap
- pass data by pointer to reduce copy in memory

## v0.6.0 (Jun 4, 2018)
- update usage
- print version if verbose
- example end of pcap is garbage
- example input is directory
- grammer, typos
- grammer
- grammer
- why
- update usage
- readme v & x
- fix print help only if err != nil (don't panic)

## v0.5.0 (Jun 4, 2018)
- bump version, fix print help
- example non exisitng file
- example partial first packet header
- skip instead of fail bad pcap files or file read errors
- example partial global header
- example empty pcap
- fix table
- readme examples
- add pcap examples
- print (skiping this packet) on errors
- print source pcap on all read errors
- also skip errors on first packet, print pcap path in logs
- *.pcap*
- smaller mount size

## v0.4.0 (Jun 4, 2018)
- disable pprof
- read from source until good packet or EOF
- fix write to stdout instead of file
- better logs

## v0.3.0 (Jun 4, 2018)
- enable write to file, better logs, fix flush write buffer
- bump version

## v0.2.0 (Jun 1, 2018)
- bump version
- default buffer size
- update benchmarks
- use buffered writer
- clean readme
- uodate benchmark
- benchmark use tmpfs
- semantics
- refactor readme
- benchmark
- combine -h and -v
- init benchmark

## v0.1.0 (May 31, 2018)
- readme skeleton
- todo benchmark
- init (works)
