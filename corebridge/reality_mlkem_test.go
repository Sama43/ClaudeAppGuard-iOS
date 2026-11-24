//go:build with_utls

package corebridge

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
)

const (
	tlsGroupX25519MLKEM768 uint16 = 0x11ec
	tlsGroupX25519         uint16 = 0x001d
)

func captureRealityClientHello(t *testing.T, fingerprint string) (groups []uint16, keyShares []uint16) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	rawJSON := fmt.Sprintf(
		`{"enabled":true,"server_name":"www.apple.com","utls":{"enabled":true,"fingerprint":%q},"reality":{"enabled":true,"public_key":%q,"short_id":"01234567"}}`,
		fingerprint, pubB64,
	)
	ctx := include.Context(context.Background())
	opts, err := json.UnmarshalExtendedContext[option.OutboundTLSOptions](ctx, []byte(rawJSON))
	if err != nil {
		t.Fatalf("unmarshal tls options: %v", err)
	}
	cfg, err := boxtls.NewRealityClient(ctx, logger.NOP(), "www.apple.com", opts)
	if err != nil {
		t.Fatalf("NewRealityClient(%s): %v", fingerprint, err)
	}

	clientConn, serverConn := net.Pipe()
	recordCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		_ = serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(serverConn, hdr); err != nil {
			errCh <- err
			return
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		payload := make([]byte, recLen)
		if _, err := io.ReadFull(serverConn, payload); err != nil {
			errCh <- err
			return
		}
		recordCh <- payload
	}()

	hsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, _ = boxtls.ClientHandshake(hsCtx, clientConn, cfg)
	_ = clientConn.Close()

	var payload []byte
	select {
	case payload = <-recordCh:
	case err := <-errCh:
		t.Fatalf("read client hello (%s): %v", fingerprint, err)
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for client hello (%s)", fingerprint)
	}

	if len(payload) < 42 || payload[0] != 0x01 {
		t.Fatalf("unexpected TLS handshake record (len=%d, type=%d)", len(payload), payload[0])
	}
	pos := 4 + 2 + 32 // handshake header + legacy_version + random
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	compLen := int(payload[pos])
	pos += 1 + compLen
	extTotalLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	extEnd := pos + extTotalLen
	if extEnd > len(payload) {
		t.Fatalf("truncated extensions: end=%d > len=%d", extEnd, len(payload))
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		extData := payload[pos+4 : pos+4+extLen]
		pos += 4 + extLen

		switch extType {
		case 0x000a: // supported_groups
			if len(extData) < 2 {
				continue
			}
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			for p := 2; p+2 <= 2+listLen && p+2 <= len(extData); p += 2 {
				groups = append(groups, binary.BigEndian.Uint16(extData[p:p+2]))
			}
		case 0x0033: // key_share
			if len(extData) < 2 {
				continue
			}
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			for p := 2; p+4 <= 2+listLen && p+4 <= len(extData); {
				g := binary.BigEndian.Uint16(extData[p : p+2])
				kl := int(binary.BigEndian.Uint16(extData[p+2 : p+4]))
				keyShares = append(keyShares, g)
				p += 4 + kl
			}
		}
	}
	return groups, keyShares
}

// Verifies the SagerNet/sing-box#4520 REALITY ML-KEM patch:
// Xray-core v26.9.8+ requires X25519MLKEM768 ahead of X25519 in Chrome REALITY ClientHello.
func TestRealityClientHelloPreservesMLKEMForChrome(t *testing.T) {
	groups, keyShares := captureRealityClientHello(t, "chrome")

	if !slices.Contains(groups, tlsGroupX25519MLKEM768) {
		t.Fatalf("chrome REALITY ClientHello missing X25519MLKEM768 in supported_groups: %x", groups)
	}
	mlkemIdx := slices.Index(keyShares, tlsGroupX25519MLKEM768)
	x25519Idx := slices.Index(keyShares, tlsGroupX25519)
	if mlkemIdx < 0 {
		t.Fatalf("chrome REALITY ClientHello missing X25519MLKEM768 in key_share: %x", keyShares)
	}
	if x25519Idx < 0 {
		t.Fatalf("chrome REALITY ClientHello missing X25519 in key_share: %x", keyShares)
	}
	if mlkemIdx > x25519Idx {
		t.Fatalf("chrome REALITY ClientHello must place X25519MLKEM768 ahead of X25519: %x", keyShares)
	}
}

func TestRealityClientHelloRandomizedMLKEMPairConsistent(t *testing.T) {
	groups, keyShares := captureRealityClientHello(t, "randomized")
	hasGroup := slices.Contains(groups, tlsGroupX25519MLKEM768)
	hasShare := slices.Contains(keyShares, tlsGroupX25519MLKEM768)
	if hasGroup != hasShare {
		t.Fatalf("randomized REALITY ClientHello has mismatched ML-KEM group (%v) and share (%v)", hasGroup, hasShare)
	}
}
