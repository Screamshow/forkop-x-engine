package urltest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type timingStore struct {
	adapter.CertificateStore
	roots *x509.CertPool
}

func (s timingStore) Pool() *x509.CertPool { return s.roots }

type timingDialer struct {
	wait  time.Duration
	calls int
}

func (d *timingDialer) DialContext(ctx context.Context, network string, addr M.Socksaddr) (net.Conn, error) {
	d.calls++
	select {
	case <-time.After(d.wait):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr.String())
}
func (d *timingDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("unused")
}

func timingServer(t *testing.T) (*httptest.Server, context.Context) {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Connection", "close") // no warm-up/keep-alive required
		w.WriteHeader(http.StatusNoContent)
	}))
	s.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		time.Sleep(350 * time.Millisecond)
		return nil, nil
	}}
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	ctx := service.ContextWith[adapter.CertificateStore](context.Background(), timingStore{roots: roots})
	return s, ctx
}

func TestXDelayExcludesDialAndTLS(t *testing.T) {
	s, ctx := timingServer(t)
	d := &timingDialer{wait: 150 * time.Millisecond}
	started := time.Now()
	ms, err := URLTest(ctx, s.URL, d)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 500*time.Millisecond {
		t.Fatal("handshake was not exercised")
	}
	if ms < 40 || ms >= 250 {
		t.Fatalf("request delay includes setup or loses response time: %d", ms)
	}
	if d.calls != 1 {
		t.Fatalf("unexpected extra connection: %d", d.calls)
	}
}

func TestXHandshakeStillUsesTimeout(t *testing.T) {
	s, ctx := timingServer(t)
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := URLTest(ctx, s.URL, &timingDialer{}); err == nil {
		t.Fatal("TLS timeout must remain a failed test")
	}
}
