# joincap

Merge multiple pcap files together.

## Why?

`TODO: tcpslice dies when can't find the last packet?`  
`TODO: mergecap dies on every corrupt packet/header?`  
I think skipping corrupt packets is better than failing the entire merge job.

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
3.25GiB 0:00:06 [ 506MiB/s]

real    0m6.571s
user    0m4.801s
sys     0m4.793s

tcpslice:
Version 1.2a3
Usage: tcpslice [-DdlRrt] [-w file] [start-time [end-time]] file ...
3.00GiB 0:00:04 [ 708MiB/s]

real    0m4.337s
user    0m2.955s
sys     0m4.146s

joincap:
joincap v0.1.0
Usage: joincap <infile> [<infile>...]
3.00GiB 0:00:41 [73.3MiB/s]

real    0m41.909s
user    0m32.958s
sys     0m51.939s
```
