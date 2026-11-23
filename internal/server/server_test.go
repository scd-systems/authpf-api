package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Echo v5 handed the StartTLS path arguments to an fs.FS (default
// os.DirFS(".")), which rejects every name that is not fs.ValidPath. Absolute
// certificate paths therefore aborted startup with
// "readfile /…/server.crt: invalid argument" although Validate() had accepted
// the very same files with OS path semantics. startServer now feeds Echo a
// loaded key pair, so every path form the OS accepts has to serve HTTPS.
func TestStartServerServesHTTPSForEveryPathForm(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, certPEM := writeTestKeyPair(t, dir, "server")
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0750))

	tests := []struct {
		name  string
		cert  string
		key   string
		chdir bool
	}{
		{name: "absolute path", cert: certPath, key: keyPath},
		{name: "leading dot segment", cert: "./server.crt", key: "./server.key", chdir: true},
		{name: "dot-dot segment", cert: "sub/../server.crt", key: "sub/../server.key", chdir: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.chdir {
				t.Chdir(dir)
			}
			baseURL := startTLSTestServer(t, tt.cert, tt.key)

			// The key pair is loaded before Echo binds, so a reachable port also
			// proves the configured path form was accepted.
			resp, body := httpsGet(t, baseURL+"/ping", certPEM, 0)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "pong", body)
			assert.GreaterOrEqual(t, resp.TLS.Version, uint16(tls.VersionTLS12))
		})
	}
}

// The minimum version stays TLS 1.2 on purpose: clients without TLS 1.3 (for
// example LibreSSL builds such as macOS /usr/bin/curl) must still connect.
func TestStartServerAcceptsTLS12Clients(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, certPEM := writeTestKeyPair(t, dir, "server")
	baseURL := startTLSTestServer(t, certPath, keyPath)

	resp, body := httpsGet(t, baseURL+"/ping", certPEM, tls.VersionTLS12)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "pong", body)
	assert.Equal(t, uint16(tls.VersionTLS12), resp.TLS.Version, "the client capped at TLS 1.2 has to be served TLS 1.2")
}

// A broken pair must stop the server instead of listening without a certificate.
func TestStartServerRejectsMismatchedKeyPair(t *testing.T) {
	dir := t.TempDir()
	certPath, _, _ := writeTestKeyPair(t, dir, "server-a")
	_, keyPathB, _ := writeTestKeyPair(t, dir, "server-b")

	srv := tlsTestServer(t, certPath, keyPathB)
	e := echo.New()

	err := srv.startServer(e)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SSL certificate/key pair")
	assert.Contains(t, err.Error(), certPath)
	assert.Contains(t, err.Error(), keyPathB)
}

// startTLSTestServer runs the real startServer on a free port and returns its
// https base URL. Like the other server tests the listener lives until the test
// binary exits.
func startTLSTestServer(t *testing.T, certPath, keyPath string) string {
	t.Helper()

	srv := tlsTestServer(t, certPath, keyPath)
	e := echo.New()
	e.GET("/ping", func(c *echo.Context) error { return c.String(http.StatusOK, "pong") })

	go func() {
		_ = srv.startServer(e)
	}()

	return fmt.Sprintf("https://%s:%d", srv.config.Server.Bind, srv.config.Server.Port)
}

func tlsTestServer(t *testing.T, certPath, keyPath string) *Server {
	t.Helper()

	return &Server{
		config: &config.ConfigFile{
			Server: config.ConfigFileServer{
				Bind: "127.0.0.1",
				Port: freeTestPort(t),
				SSL:  config.ConfigFileServerSSL{Certificate: certPath, Key: keyPath},
			},
		},
		logger: zerolog.New(zerolog.ConsoleWriter{Out: io.Discard}),
	}
}

// httpsGet retries until the listener is up. maxVersion 0 keeps the Go default.
func httpsGet(t *testing.T, url, certPEM string, maxVersion uint16) (*http.Response, string) {
	t.Helper()

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM([]byte(certPEM)))
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: maxVersion},
	}}

	var resp *http.Response
	var err error
	for attempt := 0; attempt < 100; attempt++ {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NoError(t, err, "server did not answer on %s", url)

	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NotNil(t, resp.TLS, "the response must come from a TLS listener")

	return resp, string(body)
}

// freeTestPort takes a port from the ephemeral range. The listener is closed
// right away, so the port is only guaranteed for a moment — the retry loop of
// httpsGet absorbs the remaining race.
func freeTestPort(t *testing.T) uint16 {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())

	return port
}

// writeTestKeyPair writes a self-signed pair valid for localhost/127.0.0.1 and
// returns certificate path, key path and the certificate PEM for verification.
func writeTestKeyPair(t *testing.T, dir, commonName string) (string, string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath := filepath.Join(dir, commonName+".crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, commonName+".key")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600))

	return certPath, keyPath, string(certPEM)
}
