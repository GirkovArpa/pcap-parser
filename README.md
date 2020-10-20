# PCAP PARSER

A `.pcap` file parser, written in JavaScript for NodeJS.

## Usage

```
$ FILENAME=capture.pcap node index
```

## Todo

- [x] Parse `.pcap` files containing only UDP packets.
- [ ] Parse `.pcap` files containing TCP packets.
- [ ] Correctly parse the `fragment_offset` field of the `ipv4_header`.

## Note

Only tested on a `.pcap` file produced by the C program found [here](https://github.com/nospaceships/raw-socket-sniffer).
