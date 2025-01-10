package echcheck

import (
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
		// This will be used as the inner SNI and we will validate
		// we get a certificate for this name.  The outer SNI will
		// be set based on the ECH config.
		ServerName:         parsed.Hostname(),
		InsecureSkipVerify: true,
		RootCAs:            testPool,
	}

	fmt.Printf("parsed: %v\n", parsed.Host)
	result := handshake([]byte{}, false, false, time.Now(), parsed.Host, parsed, model.DiscardLogger, tlsConfig)

	if result.SoError != nil {
		t.Fatal("did not expect error, got: ", result.SoError)
	}

	if result.Failure != nil {
		t.Fatal("did not expect error, got: ", *result.Failure)
	}

}
