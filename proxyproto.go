// proxyproto.go
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// == PROXY Protocol v2 constants ===============================================
//
// Reference: HAProxy PROXY Protocol Specification §2.2
// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

// pp2Sig is the 12-byte magic that opens every v2 header.  It is deliberately
// not valid UTF-8 and not a valid v1 header, so v1-only receivers reject it
// immediately rather than silently misinterpreting it.
var pp2Sig = []byte{
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
	0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
}

const (
	// Version/command byte.
	// High nibble = 2 (protocol version 2).
	// Low  nibble = 1 (PROXY command — carry originating connection addresses).
	pp2VerCmd = 0x21

	// Combined address-family | transport-protocol bytes.
	pp2IPv4TCP = 0x11 // AF_INET  (0x10) | SOCK_STREAM (0x01)
	pp2IPv6TCP = 0x21 // AF_INET6 (0x20) | SOCK_STREAM (0x01)

	// Byte lengths of the address+port block for each address family.
	pp2AddrLenIPv4 = 12 // src_addr(4) + dst_addr(4) + src_port(2) + dst_port(2)
	pp2AddrLenIPv6 = 36 // src_addr(16) + dst_addr(16) + src_port(2) + dst_port(2)

	// PP2_TYPE_SSL — outer TLV type that wraps all TLS metadata.
	pp2TypeSSL = 0x20

	// PP2_CLIENT_SSL — bit flag carried in the first byte of the PP2_TYPE_SSL
	// value, indicating the incoming connection was established over TLS.
	pp2ClientSSL = 0x01

	// Sub-TLV types nested inside PP2_TYPE_SSL.
	pp2SubSSLVersion = 0x21 // PP2_SUBTYPE_SSL_VERSION — e.g. "TLSv1.3"
	pp2SubSSLCipher  = 0x23 // PP2_SUBTYPE_SSL_CIPHER  — e.g. "TLS_AES_256_GCM_SHA384"
)

// ProxyProtocolHeader builds a binary HAProxy PROXY Protocol v2 header for
// the given queue item and returns it as a byte slice.
//
// The header encodes:
//   - Source IP (and port when present) from qi.Message.ClientIP.
//   - Destination IP:port resolved from backendAddr.
//   - A PP2_TYPE_SSL TLV when qi.Message.TLSUsed is true, carrying
//     PP2_CLIENT_SSL, PP2_SUBTYPE_SSL_VERSION, and PP2_SUBTYPE_SSL_CIPHER.
//
// The caller must write the returned bytes to the backend net.Conn immediately
// before reading the SMTP banner; the spec requires the header to precede all
// other data on the connection.
func ProxyProtocolHeader(qi *QueueItem) ([]byte, error) {
	// == 1. Parse source address ===============================================
	//
	srcIP, srcPort, err := parseHostPort(qi.Message.ClientIP)
	if err != nil {
		return nil, err
	}

	// == 2. Parse / resolve destination address ================================
	//
	dstIP, dstPort, err := parseHostPort(qi.Message.ServerIP)
	if err != nil {
		return nil, err
	}

	// == 3. Select address family and encode the address block =================
	//
	// Prefer AF_INET when both addresses have a 4-byte representation; this
	// keeps the header compact and is the common case for IPv4-only deployments.
	// Fall back to AF_INET6 when either address is pure IPv6; net.IP.To16()
	// maps any IPv4 address to its IPv4-in-IPv6 form transparently.
	var (
		familyProto byte
		addrBlock   []byte
	)
	src4, dst4 := srcIP.To4(), dstIP.To4()
	switch {
	case src4 != nil && dst4 != nil:
		familyProto = pp2IPv4TCP
		addrBlock = make([]byte, pp2AddrLenIPv4)
		copy(addrBlock[0:4], src4)
		copy(addrBlock[4:8], dst4)
		binary.BigEndian.PutUint16(addrBlock[8:10], uint16(srcPort))
		binary.BigEndian.PutUint16(addrBlock[10:12], uint16(dstPort))
	default:
		familyProto = pp2IPv6TCP
		addrBlock = make([]byte, pp2AddrLenIPv6)
		copy(addrBlock[0:16], srcIP.To16())
		copy(addrBlock[16:32], dstIP.To16())
		binary.BigEndian.PutUint16(addrBlock[32:34], uint16(srcPort))
		binary.BigEndian.PutUint16(addrBlock[34:36], uint16(dstPort))
	}

	// == 4. Build TLV extensions ===============================================
	var tlvs []byte
	if qi.Message.TLSUsed {
		tlvs = pp2BuildSSLTLV(qi.Message.TLSVersion, qi.Message.TLSCipher)
	}

	// == 5. Assemble the complete header =======================================
	//
	// Fixed 16-byte prefix layout:
	//   [0 :12]  12 bytes  signature
	//   [12:13]   1 byte   version | command
	//   [13:14]   1 byte   address family | transport protocol
	//   [14:16]   2 bytes  uint16 BE — byte length of everything that follows
	// Followed by the address block and zero or more TLVs.
	payloadLen := len(addrBlock) + len(tlvs)
	if payloadLen > 0xFFFF {
		// Unreachable with normal TLS metadata, but guard the uint16 cast.
		return nil, fmt.Errorf("proxy protocol: payload length %d overflows uint16", payloadLen)
	}

	hdr := make([]byte, 0, 16+payloadLen)
	hdr = append(hdr, pp2Sig...)
	hdr = append(hdr, pp2VerCmd, familyProto)
	hdr = append(hdr, byte(payloadLen>>8), byte(payloadLen))
	hdr = append(hdr, addrBlock...)
	hdr = append(hdr, tlvs...)
	return hdr, nil
}

// pp2BuildSSLTLV constructs a PP2_TYPE_SSL (0x20) TLV.
//
// The value portion mirrors struct pp2_tlv_ssl from the HAProxy spec:
//
//	Offset  Size  Field
//	  0      1    client  PP2_CLIENT_SSL (0x01) — connection used TLS
//	  1      4    verify  0x00000000 — no client-certificate check performed
//	  5+     …    nested sub-TLVs (SSL_VERSION, SSL_CIPHER)
//
// Sub-TLVs for empty strings are omitted rather than written with zero-length
// values, keeping the header as short as possible.
func pp2BuildSSLTLV(version, cipher string) []byte {
	// Encode sub-TLVs first so we know the total value length before writing
	// the outer length field.
	var sub []byte
	if version != "" {
		sub = append(sub, pp2MakeTLV(pp2SubSSLVersion, []byte(version))...)
	}
	if cipher != "" {
		sub = append(sub, pp2MakeTLV(pp2SubSSLCipher, []byte(cipher))...)
	}

	// Outer TLV:  type(1) + length(2) + client(1) + verify(4) + sub-TLVs
	valueLen := 1 + 4 + len(sub)
	tlv := make([]byte, 3+valueLen)
	tlv[0] = pp2TypeSSL
	binary.BigEndian.PutUint16(tlv[1:3], uint16(valueLen))
	tlv[3] = pp2ClientSSL                   // client flags
	binary.BigEndian.PutUint32(tlv[4:8], 0) // verify = 0
	copy(tlv[8:], sub)
	return tlv
}

// pp2MakeTLV encodes a single TLV triplet: type(1) + length(2) + value(n).
func pp2MakeTLV(typ byte, value []byte) []byte {
	b := make([]byte, 3+len(value))
	b[0] = typ
	binary.BigEndian.PutUint16(b[1:3], uint16(len(value)))
	copy(b[3:], value)
	return b
}

func parseHostPort(addr string) (net.IP, uint64, error) {
	// ClientIP may be a bare address ("203.0.113.1", "2001:db8::1") or an
	// address+port pair ("203.0.113.1:54321", "[2001:db8::1]:54321").
	// Both forms are accepted; the port defaults to 0 when absent.
	ipStr, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// No port separator — treat the entire value as a bare IP address.
		ipStr, portStr = addr, "0"
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, 0, fmt.Errorf("proxy protocol: invalid source IP %q", ipStr)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("proxy protocol: invalid source port %q: %w", portStr, err)
	}
	return ip, port, nil
}
