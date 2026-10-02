package main

// The public route must come from DNS packets sent to the configured resolver.
// net.Resolver.LookupHost can return /etc/hosts without calling Resolver.Dial,
// so the probe uses the Resolver's pinned Dial transport for A/AAAA queries.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	publicDNSA     = 1
	publicDNSCNAME = 5
	publicDNSAAAA  = 28
	publicDNSIN    = 1
)

type configuredPublicResolver struct {
	resolver *net.Resolver
}

func newConfiguredPublicResolver(address string, timeout time.Duration) (publicResolver, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return nil, fmt.Errorf("--resolver must be an IP address and port: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("--resolver host %q must be an IP literal, so resolving it cannot use the system resolver", host)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("--resolver port %q must be 1..65535", port)
	}
	endpoint := net.JoinHostPort(ip.String(), strconv.Itoa(portNumber))
	dialer := &net.Dialer{Timeout: timeout}
	return &configuredPublicResolver{resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network != "udp" && network != "tcp" {
				return nil, fmt.Errorf("unsupported public DNS transport %q", network)
			}
			return dialer.DialContext(ctx, network, endpoint)
		},
	}}, nil
}

func (r *configuredPublicResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	name, err := publicDNSName(host)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for len(seen) < 8 {
		if seen[name] {
			return nil, fmt.Errorf("public DNS CNAME cycle for %s", host)
		}
		seen[name] = true
		var addresses []string
		var alias string
		var queryErr error
		for _, qtype := range []uint16{publicDNSA, publicDNSAAAA} {
			answer, cname, err := r.query(ctx, name, qtype)
			if err != nil {
				queryErr = err
				continue
			}
			addresses = append(addresses, answer...)
			if cname != "" {
				alias = cname
			}
		}
		if len(addresses) > 0 {
			return addresses, nil
		}
		if alias != "" {
			name = alias
			continue
		}
		return nil, queryErr
	}
	return nil, fmt.Errorf("public DNS CNAME chain exceeds eight names for %s", host)
}

func publicDNSName(host string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if name == "" || len(name) > 253 {
		return "", fmt.Errorf("invalid public DNS host %q", host)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid public DNS host %q", host)
		}
		for _, char := range label {
			if !('a' <= char && char <= 'z') && !('0' <= char && char <= '9') && char != '-' {
				return "", fmt.Errorf("invalid public DNS host %q", host)
			}
		}
	}
	return name, nil
}

func (r *configuredPublicResolver) query(ctx context.Context, name string, qtype uint16) ([]string, string, error) {
	request, id, err := publicDNSQuestion(name, qtype)
	if err != nil {
		return nil, "", err
	}
	for _, network := range []string{"udp", "tcp"} {
		response, err := r.exchange(ctx, network, request)
		if err != nil {
			return nil, "", err
		}
		addresses, alias, truncated, err := publicDNSAnswer(response, id, name, qtype)
		if err != nil {
			return nil, "", err
		}
		if !truncated {
			return addresses, alias, nil
		}
	}
	return nil, "", errors.New("public DNS reply is truncated over TCP")
}

func publicDNSQuestion(name string, qtype uint16) ([]byte, uint16, error) {
	var randomID [2]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(randomID[:])
	request := make([]byte, 12)
	binary.BigEndian.PutUint16(request[:2], id)
	request[2] = 1 // recursion desired
	request[5] = 1 // one question
	for _, label := range strings.Split(name, ".") {
		request = append(request, byte(len(label)))
		request = append(request, label...)
	}
	request = append(request, 0, byte(qtype>>8), byte(qtype), 0, publicDNSIN)
	return request, id, nil
}

func (r *configuredPublicResolver) exchange(ctx context.Context, network string, request []byte) ([]byte, error) {
	conn, err := r.resolver.Dial(ctx, network, "")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if network == "tcp" {
		framed := make([]byte, 2, len(request)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(request)))
		framed = append(framed, request...)
		for len(framed) > 0 {
			n, err := conn.Write(framed)
			if err != nil {
				return nil, err
			}
			framed = framed[n:]
		}
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		response := make([]byte, binary.BigEndian.Uint16(size[:]))
		_, err := io.ReadFull(conn, response)
		return response, err
	}
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}
	return response[:n], nil
}

func publicDNSAnswer(packet []byte, id uint16, name string, qtype uint16) ([]string, string, bool, error) {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[:2]) != id || packet[2]&0x80 == 0 || packet[2]&0x78 != 0 {
		return nil, "", false, errors.New("invalid public DNS response header")
	}
	if packet[2]&0x02 != 0 {
		return nil, "", true, nil
	}
	rcode := packet[3] & 0x0f
	if rcode == 3 {
		return nil, "", false, nil // NXDOMAIN
	}
	if rcode != 0 {
		return nil, "", false, fmt.Errorf("public DNS response code %d", rcode)
	}
	if binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return nil, "", false, errors.New("public DNS response has the wrong question count")
	}
	question, offset, err := publicDNSReadName(packet, 12)
	if err != nil || offset+4 > len(packet) || question != name || binary.BigEndian.Uint16(packet[offset:offset+2]) != qtype || binary.BigEndian.Uint16(packet[offset+2:offset+4]) != publicDNSIN {
		return nil, "", false, errors.New("public DNS response question does not match")
	}
	offset += 4
	addresses := map[string][]string{}
	aliases := map[string]string{}
	for i := 0; i < int(binary.BigEndian.Uint16(packet[6:8])); i++ {
		owner, next, err := publicDNSReadName(packet, offset)
		if err != nil || next+10 > len(packet) {
			return nil, "", false, errors.New("invalid public DNS answer record")
		}
		rtype := binary.BigEndian.Uint16(packet[next : next+2])
		rclass := binary.BigEndian.Uint16(packet[next+2 : next+4])
		size := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
		start := next + 10
		offset = start + size
		if offset > len(packet) {
			return nil, "", false, errors.New("truncated public DNS answer record")
		}
		if rclass != publicDNSIN {
			continue
		}
		if rtype == publicDNSCNAME {
			alias, _, err := publicDNSReadName(packet, start)
			if err != nil {
				return nil, "", false, err
			}
			aliases[owner] = alias
		}
		if rtype == qtype && (rtype == publicDNSA && size == net.IPv4len || rtype == publicDNSAAAA && size == net.IPv6len) {
			addresses[owner] = append(addresses[owner], net.IP(packet[start:offset]).String())
		}
	}
	current := name
	for i := 0; i < 8; i++ {
		if len(addresses[current]) > 0 {
			return addresses[current], "", false, nil
		}
		alias := aliases[current]
		if alias == "" {
			if current != name {
				return nil, current, false, nil
			}
			return nil, "", false, nil
		}
		current = alias
	}
	return nil, "", false, errors.New("public DNS CNAME chain exceeds eight names")
}

func publicDNSReadName(packet []byte, offset int) (string, int, error) {
	var labels []string
	next := offset
	jumped := false
	for hops := 0; hops < 128; hops++ {
		if offset >= len(packet) {
			return "", 0, errors.New("truncated public DNS name")
		}
		size := int(packet[offset])
		if size&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return "", 0, errors.New("truncated public DNS name pointer")
			}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = (size&0x3f)<<8 | int(packet[offset+1])
			continue
		}
		if size&0xc0 != 0 || size > 63 || offset+1+size > len(packet) {
			return "", 0, errors.New("invalid public DNS name label")
		}
		offset++
		if size == 0 {
			if !jumped {
				next = offset
			}
			return strings.ToLower(strings.Join(labels, ".")), next, nil
		}
		labels = append(labels, string(packet[offset:offset+size]))
		offset += size
	}
	return "", 0, errors.New("public DNS name pointer cycle")
}
