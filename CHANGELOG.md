# Changelog
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
