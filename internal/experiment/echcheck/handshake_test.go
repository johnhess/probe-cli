package echcheck

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ooni/probe-cli/v3/internal/model"
)

func TestNoEchHandshake(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "success")
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	testPool := x509.NewCertPool()
	testPool.AddCert(ts.Certificate())
	tlsConfig := &tls.Config{
		ServerName:         parsed.Hostname(),
		InsecureSkipVerify: true,
		RootCAs:            testPool,
	}

	result := handshake([]byte{}, false, time.Now(), parsed.Host, parsed, model.DiscardLogger, tlsConfig)

	if result.SoError != nil {
		t.Fatal("did not expect error, got: ", result.SoError)
	}

	if result.Failure != nil {
		t.Fatal("did not expect error, got: ", *result.Failure)
	}

	if result.OuterServerName != "" {
		t.Fatal("expected OuterServerName to be empty, got: ", result.OuterServerName)
	}

}
func TestFailToEstablishECHHandshake(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "success")
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	testPool := x509.NewCertPool()
	testPool.AddCert(ts.Certificate())

	ecl, err := generateGreaseyECHConfigList(rand.Reader, parsed.Hostname())
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		EncryptedClientHelloConfigList: ecl,
		ServerName:                     parsed.Hostname(),
		RootCAs:                        testPool,
	}

	// We're using a GREASE ECHConfigList, but we'll handle it as if it's a genuine one (isGrease=False)
	// Test server doesn't handle ECH yet, so it wouldn't send retry configs anyways.
	result := handshake(ecl, false, time.Now(), parsed.Host, parsed, model.DiscardLogger, tlsConfig)

	if result.ServerName != parsed.Hostname() {
		t.Fatal("expected ServerName to be set to ts.URL.Hostname(), got: ", result.ServerName)
	}

	if result.SoError != nil {
		t.Fatal("did not expect error, got: ", result.SoError)
	}

	if result.Failure == nil || !strings.Contains(*result.Failure, "tls: server rejected ECH") {
		t.Fatal("server should have rejected ECH: ", *result.Failure)
	}
}

func TestGREASEyECHHandshake(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "success")
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	testPool := x509.NewCertPool()
	testPool.AddCert(ts.Certificate())

	ecl, err := generateGreaseyECHConfigList(rand.Reader, parsed.Hostname())
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		EncryptedClientHelloConfigList: ecl,
		ServerName:                     parsed.Hostname(),
		RootCAs:                        testPool,
	}

	result := handshake(ecl, true, time.Now(), parsed.Host, parsed, model.DiscardLogger, tlsConfig)

	if result.ECHConfig != "GREASE" {
		t.Fatal("expected ECHConfig to be GREASE, got: ", result.ECHConfig)
	}

	if result.SoError != nil {
		t.Fatal("did not expect error, got: ", result.SoError)
	}

	if result.Failure == nil || !strings.Contains(*result.Failure, "tls: server rejected ECH") {
		t.Fatal("expected Connection to fail because test server doesn't handle ECH yet")
	}
}

// TODO: Add a test case with Real ECH once the server-side of crypto/tls supports it.
