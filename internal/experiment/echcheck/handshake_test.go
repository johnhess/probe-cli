package echcheck

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	if result.SoError != nil {
		t.Fatal("did not expect error, got: ", result.SoError)
	}

	if result.Failure == nil || (*result.Failure != "unknown_failure: tls: server rejected ECH") {
		t.Fatal("server should have rejected ECH: ", *result.Failure)
	}
}

// TODO: Add a test case with Real ECH once the server-side of crypto/tls supports it.
