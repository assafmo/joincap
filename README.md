# joincap

Merge multiple pcap files together.

## Why?

`tcpslice dies when can't find the last packet?`
`mergecap dies on every corrupt packet/header?`
I think skipping corrupt packets is better than failing the whole merge.

## Install

```bash
go get -u github.com/assafmo/joincap
```

## Usage

```bash
joincap <infile> [<infile>...] > merged.pcap
```

### Benchmarks

`TODO`
