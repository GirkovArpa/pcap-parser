'use strict';

// $ FILENAME=capture.pcap node index

const { FILENAME } = process.env;

const fs = require('fs');
const buffer = fs.readFileSync(FILENAME);

function decode(buffer) {
  return new TextDecoder().decode(buffer);
}

function read_pcap_file_header(buffer, offset) {
  const magic_number = buffer.readUInt32LE(offset).toString(16); offset += 32 / 8;
  const version_major = buffer.readUInt16LE(offset); offset += 16 / 8;
  const version_minor = buffer.readUInt16LE(offset); offset += 16 / 8;
  const thiszone = buffer.readInt32LE(offset); offset += 32 / 8;
  const sigfigs = buffer.readInt32LE(offset); offset += 32 / 8;
  const snaplen = buffer.readInt32LE(offset); offset += 32 / 8;
  const linktype = buffer.readInt32LE(offset); offset += 32 / 8;
  const pcap_file_header = {
    magic_number,
    version_major,
    version_minor,
    thiszone,
    sigfigs,
    snaplen,
    linktype
  };
  return { pcap_file_header, offset };
}

function read_pcap_timeval(buffer, offset) {
  const tv_sec = buffer.readInt32LE(offset);
  offset += 32 / 8;
  const tv_usec = buffer.readInt32LE(offset);
  offset += 32 / 8;
  const pcap_timeval = { tv_sec, tv_usec };
  return { pcap_timeval, offset };
}

function read_pcap_ethernet_header(buffer, offset) {
  const mac_addr_dst = buffer.slice(offset, offset + 6).toString('hex').match(/../g).join(':');
  offset += 6;
  const mac_addr_src = buffer.slice(offset, offset + 6).toString('hex').match(/../g).join(':');
  offset += 6;
  const eth_type = buffer.readUInt16LE(offset);
  offset += 2;
  const ethernet_header = { mac_addr_dst, mac_addr_src, eth_type };
  return { ethernet_header, offset };
}

function read_pcap_sf_pkthdr(buffer, offset) {
  const { pcap_timeval: ts, offset: new_offset } = read_pcap_timeval(buffer, offset);
  offset = new_offset;
  const caplen = buffer.readUInt32LE(offset);
  offset += 32 / 8;
  const len = buffer.readUInt32LE(offset);
  offset += 32 / 8;
  const pcap_sf_pkthdr = { ts, caplen, len };
  return { pcap_sf_pkthdr, offset };
}

function read_pcap_ipv4_header(buffer, offset) {
  const ip_version_number = parseInt(buffer[offset].toString(16)[0], 16);
  offset += 0; // not a typo
  const ihl = parseInt(buffer[offset].toString(16)[1], 16);
  offset += 1;
  const service_type = buffer[offset];
  offset += 1;
  const total_length = buffer.readUInt16LE(offset);
  offset += 16 / 8;
  const id = buffer.readUInt16LE(offset);
  offset += 16 / 8;
  const flags = parseInt(buffer[offset].toString(16)[0], 16);
  offset += 0; // not a typo
  const fragment_offset = ((buffer[offset] & 0x0F) << 8) | (buffer[offset + 1] & 0xff); // needs to be fixed
  offset += 2;
  const time_to_live = buffer[offset];
  offset += 1;
  const protocol = buffer[offset];
  offset += 1;
  const header_checksum = buffer.readUInt16LE(offset);
  offset += 16 / 8;
  const src_addr = buffer.slice(offset, offset + (32 / 8)).toString('hex').match(/../g).map((byte) => parseInt(byte, 16)).join('.');
  offset += 32 / 8;
  const dst_addr = buffer.slice(offset, offset + (32 / 8)).toString('hex').match(/../g).map((byte) => parseInt(byte, 16)).join('.');
  offset += 32 / 8;
  const ipv4_header = {
    ip_version_number,
    ihl,
    service_type,
    total_length,
    id,
    flags,
    fragment_offset,
    time_to_live,
    protocol,
    header_checksum,
    src_addr,
    dst_addr
  };
  return { ipv4_header, offset };
}

function read_pcap_udp_header(buffer, offset) {
  const port_src = buffer.readUInt16BE(offset);
  offset += 16 / 8;
  const port_dst = buffer.readUInt16BE(offset);
  offset += 16 / 8;
  const length = buffer.readUInt16BE(offset);
  offset += 16 / 8;
  const checksum = buffer.readUInt16BE(offset);
  offset += 16 / 8;
  const udp_header = {
    port_src,
    port_dst,
    length,
    checksum
  };
  return { udp_header, offset };
}

function read_packet(buffer, offset, { caplen: len }) {
  const original_offset = offset;
  const { ethernet_header, offset: new_offset_a } = read_pcap_ethernet_header(buffer, offset);
  offset = new_offset_a;
  const { ipv4_header, offset: new_offset_b } = read_pcap_ipv4_header(buffer, offset);
  offset = new_offset_b;
  const { udp_header, offset: new_offset_c } = read_pcap_udp_header(buffer, offset);
  offset = new_offset_c;
  const remainder = buffer.slice(new_offset_c, original_offset + len);
  offset = original_offset + len;
  const packet = { ethernet_header, ipv4_header, udp_header, remainder: decode(remainder) };
  return { packet, offset };
}

let offset = 0;
const { pcap_file_header, offset: offset_a } = read_pcap_file_header(buffer, offset);
offset = offset_a;

console.log({ pcap_file_header });

while (offset < buffer.length) {
  const { pcap_sf_pkthdr, offset: offset_b } = read_pcap_sf_pkthdr(buffer, offset);
  offset = offset_b;
  const { packet, offset: offset_c } = read_packet(buffer, offset, pcap_sf_pkthdr);
  offset = offset_c;
  console.log({ packet });
}
