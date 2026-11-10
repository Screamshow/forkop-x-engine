//go:build with_utls

package tls

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

func TestRealityShortIDLengthBeforeDecode(t *testing.T) {
	logger, _ := newWarnLogger(t)
	options := realityOptionsForTest("chrome", true)
	options.Reality.ShortID = "0123456789abcdef01"
	_, err := NewClient(context.Background(), logger, "localhost", options)
	require.ErrorContains(t, err, "invalid short_id")
	options.Reality.ShortID = "0123456789abcdef"
	_, err = NewClient(context.Background(), logger, "localhost", options)
	require.NoError(t, err)
}

// Inspect the actual serialized first flight, rather than just the template.
func TestChrome155FirstFlight(t *testing.T) {
	for _, name := range []string{"", "chrome", "chrome_psk", "chrome_pq"} {
		t.Run(name, func(t *testing.T) {
			id, err := uTLSClientHelloID(name)
			require.NoError(t, err)
			require.Equal(t, helloChrome155, id)
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			conn, err := newUClient(a, &utls.Config{ServerName: "localhost"}, id)
			require.NoError(t, err)
			require.NoError(t, conn.BuildHandshakeState())
			raw := conn.HandshakeState.Hello.Raw
			// Handshake header, legacy version, random, session ID, cipher suites,
			// compression and then the serialized extension vector.
			offset := 4 + 2 + 32
			offset += 1 + int(raw[offset])
			offset += 2 + int(binary.BigEndian.Uint16(raw[offset:]))
			offset += 1 + int(raw[offset])
			extensions := raw[offset+2:]
			seen := map[uint16][]byte{}
			for len(extensions) > 0 {
				require.GreaterOrEqual(t, len(extensions), 4)
				typ := binary.BigEndian.Uint16(extensions)
				size := int(binary.BigEndian.Uint16(extensions[2:]))
				require.GreaterOrEqual(t, len(extensions), size+4)
				seen[typ] = extensions[4 : 4+size]
				extensions = extensions[4+size:]
			}
			require.Equal(t, chrome155TrustAnchors, seen[0xca34])
			sigs := seen[13]
			require.Equal(t, []byte{0x09, 0x04, 0x09, 0x05, 0x09, 0x06}, sigs[4:10])
			grease := binary.BigEndian.Uint16(sigs[2:4])
			require.Equal(t, uint16(0x0a0a), grease&0x0f0f)
			shares := seen[51][2:]
			groups := map[uint16]int{}
			for len(shares) > 0 {
				group := binary.BigEndian.Uint16(shares)
				size := int(binary.BigEndian.Uint16(shares[2:]))
				groups[group] = size
				shares = shares[4+size:]
			}
			require.Equal(t, 1216, groups[uint16(utls.X25519MLKEM768)])
			require.Equal(t, 32, groups[uint16(utls.X25519)])
			require.Contains(t, seen, uint16(17613)) // ALPS, new codepoint
			require.Contains(t, seen, uint16(65037)) // GREASE ECH, not a real ECH claim
		})
	}
}
