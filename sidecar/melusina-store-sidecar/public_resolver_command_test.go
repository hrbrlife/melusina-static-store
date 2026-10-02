package main

// D41 command guard: run main's verify-public dispatch in a child process.
// Only the child's system resolver is replaced; --resolver must select the
// separate public DNS server in production code.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const d41CommandChild = "MELUSINA_D41_VERIFY_PUBLIC_COMMAND_CHILD"

type d41CommandInput struct {
	Args      []string `json:"args"`
	SystemDNS string   `json:"system_dns"`
}

func TestD41VerifyPublicCommandChild(t *testing.T) {
	raw := os.Getenv(d41CommandChild)
	if raw == "" {
		t.Skip("only runs as a verify-public child")
	}
	var input d41CommandInput
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatal(err)
	}
	if input.SystemDNS == "" {
		t.Fatal("system DNS server is required")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, input.SystemDNS)
	}}
	os.Args = append([]string{"melusina-store-sidecar", "verify-public"}, input.Args...)
	main()
}

type d41DNSServer struct {
	address string
	queries atomic.Int32
}

func startD41DNSServer(t *testing.T, answer string) *d41DNSServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &d41DNSServer{address: conn.LocalAddr().String()}
	go func() {
		packet := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFrom(packet)
			if err != nil {
				return
			}
			server.queries.Add(1)
			response, err := d41DNSResponse(packet[:n], answer)
			if err == nil {
				_, _ = conn.WriteTo(response, peer)
			}
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return server
}

// The fixture responds to one A or AAAA question. An empty answer is
// NXDOMAIN, so a local system answer cannot mask a removed public record.
func d41DNSResponse(query []byte, answer string) ([]byte, error) {
	if len(query) < 17 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, errors.New("DNS query has no single question")
	}
	offset := 12
	for {
		if offset >= len(query) {
			return nil, errors.New("DNS name is truncated")
		}
		size := int(query[offset])
		offset++
		if size == 0 {
			break
		}
		if size > 63 || offset+size > len(query) {
			return nil, errors.New("DNS label is invalid")
		}
		offset += size
	}
	if offset+4 > len(query) {
		return nil, errors.New("DNS question is truncated")
	}
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])
	question := query[12 : offset+4]
	response := make([]byte, 12, 12+len(question)+16)
	copy(response[:2], query[:2])
	response[2], response[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(response[4:6], 1)
	response = append(response, question...)
	if answer == "" {
		response[3] = 0x83 // NXDOMAIN
		return response, nil
	}
	ip := net.ParseIP(answer)
	if ip == nil {
		return nil, fmt.Errorf("invalid test address %q", answer)
	}
	var raw []byte
	if qtype == 1 {
		raw = ip.To4()
	} else if qtype == 28 && ip.To4() == nil {
		raw = ip.To16()
	}
	if raw == nil {
		return response, nil
	}
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c, byte(qtype>>8), byte(qtype), 0, 1, 0, 0, 0, 10, 0, byte(len(raw)))
	response = append(response, raw...)
	return response, nil
}

func runD41VerifyPublicCommand(t *testing.T, systemDNS string, args ...string) (int, string) {
	t.Helper()
	raw, err := json.Marshal(d41CommandInput{Args: args, SystemDNS: systemDNS})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestD41VerifyPublicCommandChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), d41CommandChild+"="+string(raw))
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("verify-public child did not run: %v: %s", err, out)
	}
	return 0, string(out)
}

func TestD41VerifyPublicCommandUsesConfiguredDNS(t *testing.T) {
	fixture := newD41ProbeFixture(t)
	config := writeTmpConfig(t, fmt.Sprintf(`{"license_nft_mint":"LIC","domain":"store.example.test","tls":{"cert_path":%q,"key_path":%q}}`, fixture.certPath, fixture.keyPath))
	for _, test := range []struct {
		name   string
		host   string
		public string
		system string
		want   string
	}{
		{"removed public record", "store.example.test", "", "127.0.0.1", storePublicProbeUnresolved},
		{"split horizon", "store.example.test", "198.51.100.20", "127.0.0.1", storePublicProbeSplitHorizon},
		{"forbidden local public answer", "store.example.test", "127.0.0.1", "127.0.0.1", storePublicProbeSplitHorizon},
		{"hosts file cannot answer for public DNS", "localhost", "", "127.0.0.1", storePublicProbeUnresolved},
	} {
		t.Run(test.name, func(t *testing.T) {
			publicDNS := startD41DNSServer(t, test.public)
			systemDNS := startD41DNSServer(t, test.system)
			code, out := runD41VerifyPublicCommand(t, systemDNS.address,
				"--config="+config, "--host="+test.host, "--resolver="+publicDNS.address, "--timeout=2s")
			if code != 1 || !strings.Contains(out, test.want) || publicDNS.queries.Load() == 0 {
				t.Fatalf("verify-public exited %d; public DNS queries=%d, system DNS queries=%d; want named refusal %s through configured DNS:\n%s", code, publicDNS.queries.Load(), systemDNS.queries.Load(), test.want, out)
			}
		})
	}
}

func TestD41VerifyPublicCommandRefusesMissingOrInvalidResolver(t *testing.T) {
	fixture := newD41ProbeFixture(t)
	config := writeTmpConfig(t, fmt.Sprintf(`{"license_nft_mint":"LIC","domain":"store.example.test","tls":{"cert_path":%q,"key_path":%q}}`, fixture.certPath, fixture.keyPath))
	systemDNS := startD41DNSServer(t, "127.0.0.1")
	for _, test := range []struct{ name, resolver, want string }{
		{"missing", "", "store_public_probe_resolver_required"},
		{"invalid", "--resolver=not-an-address", "store_public_probe_resolver_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := []string{"--config=" + config, "--host=store.example.test", "--timeout=2s"}
			if test.resolver != "" {
				args = append(args, test.resolver)
			}
			code, out := runD41VerifyPublicCommand(t, systemDNS.address, args...)
			if code != 1 || !strings.Contains(out, test.want) {
				t.Fatalf("verify-public exited %d; want %s:\n%s", code, test.want, out)
			}
		})
	}
}
