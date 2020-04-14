# joincap

Merge multiple pcap files together, gracefully.

[![CircleCI](https://circleci.com/gh/assafmo/joincap.svg?style=shield&circle-token=cd4f46d248b7601530558ae6559a20ff75a897ad)](https://circleci.com/gh/assafmo/joincap)
[![Coverage Status](https://coveralls.io/repos/github/assafmo/joincap/badge.svg?branch=master)](https://coveralls.io/github/assafmo/joincap?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/assafmo/joincap)](https://goreportcard.com/report/github.com/assafmo/joincap)
[![GoDoc](https://godoc.org/github.com/assafmo/joincap?status.svg)](https://godoc.org/github.com/assafmo/joincap)

## Installation

- Download a precompiled binary from https://github.com/assafmo/joincap/releases
- Or... Use `go get`:

  ```bash
  go get -u github.com/assafmo/joincap
  ```

- Or use Ubuntu PPA:

  ```bash
  curl -SsL https://assafmo.github.io/ppa/ubuntu/KEY.gpg | sudo apt-key add -
  sudo curl -SsL -o /etc/apt/sources.list.d/assafmo.list https://assafmo.github.io/ppa/ubuntu/assafmo.list
  sudo apt update
  sudo apt install joincap
  ```

## Basic Usage

```bash
Usage:
  joincap [OPTIONS] InFiles...

Application Options:
  -v, --verbose  Explain when skipping packets or entire input files
  -V, --version  Print the version and exit
  -w=            Sets the output filename. If the name is '-', stdout will be used (default: -)

Help Options:
  -h, --help     Show this help message
```

## Why?

I believe skipping corrupt packets is better than failing the entire merge job.  
When using `tcpslice` or `mergecap` sometimes `pcapfix` is needed to fix bad input pcap files.

1.  One option is to try and run merge (`mergecap`/`tcpslice`), if we get errors then run `pcapfix` on the bad pcaps and then run merge again.
    - Adds complexity (run -> check errors -> fix -> rerun)
    - (If errors) Demands more resources (`pcapfix` processes)
    - (If errors) Extends the total run time
2.  Another option is to run `pcapfix` on the input pcap files and then merge.
    - Extends the total run time by a lot (read and write each pcap twice instead of once)
    - Demands more storage (for the fixed pcaps)
    - Demands more resources (`pcapfix` processes)
3.  We can use `pcapfix` "in memory" with process substitution: `mergecap -w out.pcap <(pcapfix -o /dev/stdout 1.pcap) <(pcapfix -o /dev/stdout 2.pcap)`.
    - Adds complexity (build a complex command line)
    - Demands more resources (`pcapfix` processes)
    - Harder for us to use pathname expansion (e.g. `tcpslice -w out.pcap *.pcap`)
    - We have to mind the command line character limit (in case of long pathnames)
    - Doesn't work for `tcpslice` (seeks the last packets to calculate time ranges - cannot do this with pipes)

## Error handling: `joincap` vs `mergecap` vs `tcpslice`

### Results

| Use case                                                                                              | joincap            | mergecap v2.4.5    | tcpslice v1.2a3    |
| ----------------------------------------------------------------------------------------------------- | ------------------ | ------------------ | ------------------ |
| Corrupt input global header                                                                           | :heavy_check_mark: | :x:                | :x:                |
| Corrupt input packet header                                                                           | :heavy_check_mark: | :x:                | :x:                |
| Unexpectd EOF<br>(last packet data is truncated)                                                      | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Input pcap has no packets<br>(global header is ok, no first packet header)                            | :heavy_check_mark: | :heavy_check_mark: | :x:                |
| Input file size is smaller than 24 bytes<br>(global header is truncated)                              | :heavy_check_mark: | :heavy_check_mark: | :x:                |
| Input file size is between 24 and 40 bytes<br>(global header is ok, first packet header is truncated) | :heavy_check_mark: | :x:                | :x:                |
| Input file doesn't exists                                                                             | :heavy_check_mark: | :x:                | :x:                |
| Input file is a directory                                                                             | :heavy_check_mark: | :x:                | :x:                |
| Input file end is garbage                                                                             | :heavy_check_mark: | :heavy_check_mark: | :x:                |
| Input file is gzipped (.pcap.gz)                                                                      | :heavy_check_mark: | :heavy_check_mark: | :x:                |

### Error outputs

| Use case                                                                                              | Error outputs                                                                                                                                                                                                                                                                                       |
| ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Corrupt input global header                                                                           | <ul><li>`tcpslice: bad tcpdump file test_pcaps/bad_global.pcap: archaic pcap savefile format`</li><li>`mergecap: The file "test_pcaps/bad_global.pcap" contains record data that mergecap doesn't support. (pcap: major version 0 unsupported)`</li></ul>                                           |
| Corrupt input packet header                                                                           | <ul><li>tcpslice: Infinite loop?</li><li>`mergecap: The file "test_pcaps/bad_first_header.pcap" appears to be damaged or corrupt. (pcap: File has 2368110654-byte packet, bigger than maximum of 262144)`</li></ul>                                                                                 |
| Unexpectd EOF<br>(last packet data is truncated)                                                      |                                                                                                                                                                                                                                                                                                     |
| Input pcap has no packets<br>(global header is ok, no first packet header)                            | <ul><li>tcpslice: Outputs empty pcap (Only global header)</li></ul>                                                                                                                                                                                                                                 |
| Input file size is smaller than 24 bytes<br>(global header is truncated)                              | <ul><li>`tcpslice: bad tcpdump file test_pcaps/empty: truncated dump file; tried to read 4 file header bytes, only got 0`</li></ul>                                                                                                                                                                 |
| Input file size is between 24 and 40 bytes<br>(global header is ok, first packet header is truncated) | <ul><li>`tcpslice: bad status reading first packet in test_pcaps/partial_first_header.pcap: truncated dump file; tried to read 16 header bytes, only got 11`</li><li>`mergecap: The file "test_pcaps/partial_first_header.pcap" appears to have been cut short in the middle of a paket.`</li></ul> |
| Input file doesn't exists                                                                             | <ul><li>`tcpslice: bad tcpdump file ./not_here: ./not_here: No such file or directory`</li><li>`mergecap: The file "./not_here" doesn't exist.`</li></ul>                                                                                                                                           |
| Input file is a directory                                                                             | <ul><li>`tcpslice: bad tcpdump file examples: error reading dump file: Is a directory`</li><li>`mergecap: "examples" is a directory (folder), not a file.`</li></ul>                                                                                                                                |
| Input file end is garbage                                                                             | <ul><li>`tcpslice: problems finding end packet of file test_pcaps/bad_end.pcap`</li></ul>                                                                                                                                                                                                           |
| Input file is gzipped (.pcap.gz)                                                                      | <ul><li>`tcpslice: bad tcpdump file test_pcaps/ok.pcap.gz: unknown file format`</li></ul>                                                                                                                                                                                                           |

### How to reproduce

| Use case                                                                                              | How to reproduce                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Corrupt input global header                                                                           | <ul><li>`joincap -w out_joincap.pcap test_pcaps/bad_global.pcap`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/bad_global.pcap`</li><li>`tcpslice -D -w out_tcpslice.pcap test_pcaps/bad_global.pcap`</li></ul>                                                                                                                                                                                                                                                                                                                                      |
| Corrupt input packet header                                                                           | <ul><li>`joincap -w out_joincap.pcap test_pcaps/bad_first_header.pcap`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/bad_first_header.pcap`</li><li>`tcpslice -D -w out_tcpslice.pcap test_pcaps/bad_first_header.pcap`</li></ul>                                                                                                                                                                                                                                                                                                                    |
| Unexpectd EOF<br>(last packet data is truncated)                                                      | <ul><li>`joincap -w out_joincap.pcap test_pcaps/unexpected_eof_on_first_packet.pcap`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/unexpected_eof_on_first_packet.pcap`</li><li>`tcpslice -D -w out_tcpslice.pcap test_pcaps/unexpected_eof_on_first_packet.pcap`</li><li>`joincap -w out_joincap.pcap test_pcaps/unexpected_eof_on_second_packet.pcap`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/unexpected_eof_on_second_packet.pcap`</li><li>`tcpslice -D -w out_tcpslice.pcap test_pcaps/unexpected_eof_on_second_packet.pcap`</li></ul> |
| Input pcap has no packets<br>(global header is ok, no first packet header)                            | <ul><li>`joincap -w out_joincap.pcap test_pcaps/ok.pcap test_pcaps/no_packets.pcap`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/ok.pcap test_pcaps/no_packets.pcap`</li><li>`tcpslice -D -w out_tcpslice.pcap test_pcaps/ok.pcap test_pcaps/no_packets.pcap`</li></ul>                                                                                                                                                                                                                                                                             |
| Input file size is smaller than 24 bytes<br>(global header is truncated)                              | <ul><li>`joincap -w out_joincap.pcap test_pcaps/ok.pcap test_pcaps/empty`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/ok.pcap test_pcaps/empty`</li><li>`tcpslice -D -w out_tcpslice.pcap test_pcaps/ok.pcap test_pcaps/empty`</li><li>`joincap -w out_joincap.pcap test_pcaps/ok.pcap test_pcaps/partial_global_header.pcap`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/ok.pcap test_pcaps/partial_global_header.pcap`</li><li>`tcpslic -De -w out_tcpslice.pcap test_pcaps/ok.pcap test_pcaps/partial_global_header.pcap`</li></ul>       |
| Input file size is between 24 and 40 bytes<br>(global header is ok, first packet header is truncated) | <ul><li>`joincap -w out_joincap.pcap test_pcaps/ok.pcap test_pcaps/partial_first_header.pcap`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/ok.pcap test_pcaps/partial_first_header.pcap`</li><li>`tcpslic -De -w out_tcpslice.pcap test_pcaps/ok.pcap test_pcaps/partial_first_header.pcap`</li></ul>                                                                                                                                                                                                                                               |
| Input file doesn't exists                                                                             | <ul><li>`joincap -w out_joincap.pcap test_pcaps/ok.pcap ./not_here`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/ok.pcap ./not_here`</li><li>`tcpslice -D -w out_tcpslice.pcap test_pcaps/ok.pcap ./not_here`</li></ul>                                                                                                                                                                                                                                                                                                                             |
| Input file is a directory                                                                             | <ul><li>`joincap -w out_joincap.pcap test_pcaps/ok.pcap test_pcaps/`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/ok.pcap test_pcaps/`</li><li>`tcpslice -D -w out_tcpslice.pcap test_pcaps/ok.pcap test_pcaps/`</li></ul>                                                                                                                                                                                                                                                                                                                          |
| Input file end is garbage                                                                             | <ul><li>`joincap -w out_joincap.pcap test_pcaps/ok.pcap test_pcaps/bad_end.pcap`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/ok.pcap test_pcaps/bad_end.pcap`</li><li>`tcpslice -D -w out_tcpslice.pcap test_pcaps/ok.pcap test_pcaps/bad_end.pcap`</li></ul>                                                                                                                                                                                                                                                                                      |
| Input file is gzipped (.pcap.gz)                                                                      | <ul><li>`joincap -w out_joincap.pcap test_pcaps/ok.pcap.gz`</li><li>`mergecap -w out_mergecap.pcap test_pcaps/ok.pcap.gz`</li><li>`tcpslice -D -w out_tcpslice.pcap test_pcaps/ok.pcap.gz`</li></ul>                                                                                                                                                                                                                                                                                                                                                     |

## Benchmarks

|              | Version | Speed    | Time     |
| ------------ | ------- | -------- | -------- |
| **mergecap** | 3.2.2   | 590MiB/s | 0m5.632s |
| **tcpslice** | 1.2a3   | 820MiB/s | 0m3.746s |
| **joincap**  | 0.10.1  | 414MiB/s | 0m7.408s |

- Merging 3 files with total size of 2.99994GiB.
- Running on Linux 5.4.0-21-generic, with Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz (with SSE4.2), with 31765 MB of physical memory, with locale C, with zlib 1.2.11.
