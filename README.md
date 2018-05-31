# joincap

Merge multiple pcap files together.

## Install

```bash
go get -u github.com/assafmo/joincap
```

## Usage

```bash
joincap 1.pcap [2.pcap...] > merged.pcap
```

## joincap vs mergecap vs tcpslice

`TODO - tcpslice dies when can't find the last packet?`
`TODO - mergecap dies on every corrupt packet/header?`

### Benchmarks

`TODO`
