# joincap

Merge multiple pcap files together, gracefully.

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

## Error handling: `tcpslice` vs `mergecap` vs `joincap`

| Use case                                                                                           | tcpslice v1.2a3                                                                                                                                                  | mergecap v2.4.5                                                                                                                                                              | joincap                                                                 | Example                                                                                                 |
| -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Corrupt input global header                                                                        | :x: Dies with `tcpslice: bad tcpdump file examples/bad_global.pcap: archaic pcap savefile format`                                                                | :x: Dies with `mergecap: The file "examples/bad_global.pcap" contains record data that mergecap doesn't support. (pcap: major version 0 unsupported)`                        | :heavy_check_mark: Ignores the corrupt input pcap                       | Merge `examples/bad_global.pcap`                                                                        |
| Corrupt input packet header                                                                        | :x: Infinite loop?                                                                                                                                               | :x: Dies with `mergecap: The file "examples/bad_first_header.pcap" appears to be damaged or corrupt. (pcap: File has 2368110654-byte packet, bigger than maximum of 262144)` | :heavy_check_mark: Ignores the packet and tries to find the next header | Merge `examples/bad_first_header.pcap`                                                                  |
| Unexpectd EOF (last packet data is truncated)                                                      | :heavy_check_mark: Pads the last packet                                                                                                                          | :heavy_check_mark: Pads the last packet                                                                                                                                      | :heavy_check_mark: Pads the last packet                                 | Merge `examples/unexpected_eof_on_first_packet.pcap` or `examples/unexpected_eof_on_second_packet.pcap` |
| Input pcap has no packets (global header is ok, no first packet header)                            | :x: Outputs empty pcap (Only global header)                                                                                                                      | :heavy_check_mark: Ignores the empty pcap                                                                                                                                    | :heavy_check_mark: Ignores the empty input pcap                         | Merge `examples/ok.pcap` with `examples/no_packets.pcap`                                                |
| Input file size is smaller than 24 bytes (global header is truncated)                              | :x: Dies with `tcpslice: bad tcpdump file examples/empty: truncated dump file; tried to read 4 file header bytes, only got 0`                                    | :heavy_check_mark: Ignores the corrupt pcap                                                                                                                                  | :heavy_check_mark: Ignores the corrupt input pcap                       | Merge `examples/ok.pcap` with `examples/empty` or `examples/partial_global_header.pcap`                 |
| Input file size is between 24 and 40 bytes (global header is ok, first packet header is truncated) | :x: Dies with `tcpslice: bad status reading first packet in examples/partial_first_header.pcap: truncated dump file; tried to read 16 header bytes, only got 11` | :x: Dies with `mergecap: The file "examples/partial_first_header.pcap" appears to have been cut short in the middle of a packet.`                                            | :heavy_check_mark: Ignores the corrupt input pcap                       | Merge `examples/ok.pcap` with `examples/empty` or `examples/partial_global_header.pcap`                 |
| Input file doesn't exists                                                                          | :x: Dies with `tcpslice: bad tcpdump file ./not_here: ./not_here: No such file or directory`                                                                     | :x: Dies with `mergecap: The file "./not_here" doesn't exist.`                                                                                                               | :heavy_check_mark: Ignores the non existing input file                  | Merge `examples/ok.pcap` with `./not_here`                                                              |
| Input file is a directory                                                                          | :x: Dies with `tcpslice: bad tcpdump file examples: error reading dump file: Is a directory`                                                                     | :x: Dies with `mergecap: "examples" is a directory (folder), not a file.`                                                                                                    | :heavy_check_mark: Ignores the non existing input file                  | Merge `examples/ok.pcap` with `examples/`                                                               |
| Input file end is garbage                                                                          | :x: Dies with `tcpslice: problems finding end packet of file examples/bad_end.pcap`                                                                              | :heavy_check_mark: Ignores the corrupt end of the pcap                                                                                                                       | :heavy_check_mark: Ignores the corrupt end of the pcap                  | Merge `examples/ok.pcap` with `examples/bad_end.pcap`                                                   |

## Install

```bash
go get -u github.com/assafmo/joincap
```

## Usage

```bash
Usage:
  main [OPTIONS]

Application Options:
  -v, --verbose  Explain when skipping packets or entire input files.
  -V, --version  Print the version and exit.
  -w=            Sets the output filename. If the name is '-', stdout will be used. (default: -)

Help Options:
  -h, --help     Show this help message
```

## Benchmarks

**_TL;DR: `tcpslice` > `mergecap` > `joincap`._**

```
mergecap:
Mergecap (Wireshark) 2.4.5 (Git v2.4.5 packaged as 2.4.5-1)

Copyright 1998-2018 Gerald Combs <gerald@wireshark.org> and contributors.
License GPLv2+: GNU GPL version 2 or later <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>
This is free software; see the source for copying conditions. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Compiled (64-bit) with GLib 2.55.2, with zlib 1.2.11.

Running on Linux 4.15.0-22-generic, with Intel(R) Core(TM) i5-8250U CPU @
1.60GHz (with SSE4.2), with 7873 MB of physical memory, with locale C, with zlib
1.2.11.

Built using gcc 7.3.0.
3.25GiB 0:00:05 [ 605MiB/s]

real    0m5.498s
user    0m4.028s
sys     0m4.233s

tcpslice:
Version 1.2a3
Usage: tcpslice [-DdlRrt] [-w file] [start-time [end-time]] file ...
3.00GiB 0:00:03 [ 825MiB/s]

real    0m3.721s
user    0m2.402s
sys     0m3.683s

joincap:
joincap v0.2.0
Usage: joincap <infile> [<infile>...]
3.00GiB 0:00:07 [ 397MiB/s]

real    0m7.737s
user    0m12.115s
sys     0m1.811s
```
