# joincap

Merge multiple pcap files together.

## tcpslice vs mergecap vs joincap

I believe skipping corrupt packets is better than failing the entire merge job.

| Use case                                                                                                       | tcpslice                                                                                                                                                         | mergecap                                                                                                                                                                     | joincap                                                               | example                                                                                         |
| -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Corrupt input global header                                                                                    | :x: Dies with `tcpslice: bad tcpdump file examples/bad_global.pcap: archaic pcap savefile format`                                                                | :x: Dies with `mergecap: The file "examples/bad_global.pcap" contains record data that mergecap doesn't support. (pcap: major version 0 unsupported)`                        | :heavy_check_mark: Skips the corrupt input pcap                       | `examples/bad_global.pcap`                                                                      |
| Corrupt input packet header                                                                                    | :x: Infinite loop?                                                                                                                                               | :x: Dies with `mergecap: The file "examples/bad_first_header.pcap" appears to be damaged or corrupt. (pcap: File has 2368110654-byte packet, bigger than maximum of 262144)` | :heavy_check_mark: Skips the packet and tries to find the next header | `examples/bad_first_header.pcap`                                                                |
| Unexpectd EOF (last packet data is truncated)                                                                  | :heavy_check_mark: Pads the last packet                                                                                                                          | :heavy_check_mark: Pads the last packet                                                                                                                                      | :heavy_check_mark: Pads the last packet                               | `examples/unexpected_eof_on_first_packet.pcap`, `examples/unexpected_eof_on_second_packet.pcap` |
| One of the input pcaps has no packets (global header is ok, no first packet header)                            | :x: Outputs empty pcap (Only global header)                                                                                                                      | :heavy_check_mark: Skips the empty pcap                                                                                                                                      | :heavy_check_mark: Skips the empty input pcap                         | Merge `examples/ok.pcap` with `examples/no_packets.pcap`                                        |
| One of the input files size is smaller than 24 bytes (global header is truncated)                              | :x: Dies with `tcpslice: bad tcpdump file examples/empty: truncated dump file; tried to read 4 file header bytes, only got 0`                                    | :heavy_check_mark: Skips the corrupt pcap                                                                                                                                    | :heavy_check_mark: Skips the corrupt input pcap                       | Merge `examples/ok.pcap` with `examples/empty` or `examples/partial_global_header.pcap`         |
| One of the input files size is between 24 and 40 bytes (global header is ok, first packet header is truncated) | :x: Dies with `tcpslice: bad status reading first packet in examples/partial_first_header.pcap: truncated dump file; tried to read 16 header bytes, only got 11` | :x: Dies with `mergecap: The file "examples/partial_first_header.pcap" appears to have been cut short in the middle of a packet.`                                            | :heavy_check_mark: Skips the corrupt input pcap                       | Merge `examples/ok.pcap` with `examples/empty` or `examples/partial_global_header.pcap`         |
| One of the input files doesn't exists                                                                          | :x: Dies with `tcpslice: bad tcpdump file ./not_here: ./not_here: No such file or directory`                                                                     | :x: Dies with `mergecap: The file "./not_here" doesn't exist.`                                                                                                               | :heavy_check_mark: Skips the non existing input file                  | Merge `examples/ok.pcap` with `./not_here`                                                      |

`TODO: tcpslice dies when can't find the last packet?`

## Install

```bash
go get -u github.com/assafmo/joincap
```

## Usage

```bash
joincap <infile> [<infile>...] > merged.pcap
```

## Benchmarks

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
