package verify

import (
	"encoding/binary"
	"strings"
	"testing"
)

func appendU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

func appendString(dst []byte, v string) []byte {
	dst = appendU32(dst, uint32(len(v)))
	return append(dst, []byte(v)...)
}

func resellerEntryFixture(status byte) []byte {
	b := make([]byte, AccountDiscriminatorLen) // Anchor discriminator need not be interpreted here.
	b = append(b, make([]byte, 32)...)
	b = append(b, make([]byte, 32)...)
	b = append(b, make([]byte, 8)...)
	b = append(b, make([]byte, 32)...)
	b = appendString(b, "reseller")
	b = appendString(b, "territory")
	b = appendU32(b, 3)
	b = appendU32(b, 1)
	b = append(b, 1) // Some(parent_reseller)
	b = append(b, make([]byte, 32)...)
	b = appendU32(b, 4)
	b = appendU32(b, 2)
	b = append(b, 1) // Some(category)
	b = appendString(b, "infrastructure")
	b = append(b, status)
	return b
}

func TestReadResellerEntryStatusWalksVariableFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		byte byte
		want ResellerStatus
	}{
		{"active", 0, ResellerStatusActive},
		{"revoked", 1, ResellerStatusRevoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadResellerEntryStatus(resellerEntryFixture(tc.byte))
			if err != nil || got != tc.want {
				t.Fatalf("ReadResellerEntryStatus() = %v, %v; want %v, nil", got, err, tc.want)
			}
		})
	}
}

func TestReadResellerEntryStatusFailsClosedOnMalformedData(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"truncated", resellerEntryFixture(0)[:20]},
		{"unknown-status", resellerEntryFixture(9)},
		{"invalid-parent-option", func() []byte {
			b := resellerEntryFixture(0)
			// Layout through both strings + two u32 fields reaches parent option.
			off := AccountDiscriminatorLen + 32 + 32 + 8 + 32 + 4 + len("reseller") + 4 + len("territory") + 4 + 4
			b[off] = 2
			return b
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadResellerEntryStatus(tc.data)
			if err == nil {
				t.Fatal("malformed reseller entry unexpectedly decoded")
			}
			if tc.name == "unknown-status" && !strings.Contains(err.Error(), "unknown ResellerStatus") {
				t.Fatalf("unexpected unknown-status error: %v", err)
			}
		})
	}
}
