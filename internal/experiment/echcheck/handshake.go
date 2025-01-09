package echcheck

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/url"
	"time"

	"github.com/ooni/probe-cli/v3/internal/logx"
	"github.com/ooni/probe-cli/v3/internal/measurexlite"
	"github.com/ooni/probe-cli/v3/internal/model"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
)

const echExtensionType uint16 = 0xfe0d

type EchMode int

const (
	NoECH EchMode = iota
	GreaseECH
	RealECH
)

func attemptHandshake(
	ctx context.Context,
	echConfigList []byte,
	useRetryConfigs bool,
	startTime time.Time,
	address string,
	target *url.URL,
	logger model.Logger) (chan model.ArchivalTLSOrQUICHandshakeResult, error) {

	channel := make(chan model.ArchivalTLSOrQUICHandshakeResult)

	ol := logx.NewOperationLogger(logger, "echcheck: TCPConnect %s", address)
	var dialer net.Dialer
	_, err := dialer.DialContext(ctx, "tcp", address)
	ol.Stop(err)
	if err != nil {
		return nil, netxlite.NewErrWrapper(netxlite.ClassifyGenericError, netxlite.ConnectOperation, err)
	}

	go func() {
		tlsConfig := genEchTLSConfig(target.Hostname(), echConfigList)

		ol := logx.NewOperationLogger(logger, "echcheck: DialTLS")
		start := time.Now()
		maybeTLSConn, err := tls.Dial("tcp", address, tlsConfig)
		if echErr, ok := err.(*tls.ECHRejectionError); ok && useRetryConfigs {
			// This is a special case where the server rejected the ECH as expected.
			newTLSConfig := genEchTLSConfig(target.Hostname(), echErr.RetryConfigList)
			maybeTLSConn, err = tls.Dial("tcp", address, newTLSConfig)
		}
		finish := time.Now()
		ol.Stop(err)

		var connState tls.ConnectionState
		if err != nil {
			connState = tls.ConnectionState{}
		} else {
			// If there's been an error, processing maybeTLSConn can panic.
			connState = netxlite.MaybeTLSConnectionState(maybeTLSConn)
		}
		hs := measurexlite.NewArchivalTLSOrQUICHandshakeResult(0, start.Sub(startTime), "tcp", address, tlsConfig,
			connState, err, finish.Sub(startTime))
		// TODO: Support "GREASE" as a value here
		hs.ECHConfig = base64.StdEncoding.EncodeToString(echConfigList)
		if len(echConfigList) > 0 {
			configs, err := parseECHConfigList(echConfigList)
			if err != nil {
				// TODO: Handle this.
				panic("failed to parse ECH config list: " + err.Error())
			}
			hs.OuterServerName = string(configs[0].PublicName)
		}
		channel <- *hs
	}()

	return channel, nil
}

func genEchTLSConfig(host string, echConfigList []byte) *tls.Config {
	if len(echConfigList) == 0 {
		return &tls.Config{ServerName: host}
	}
	return &tls.Config{
		EncryptedClientHelloConfigList: echConfigList,
		// This will be used as the inner SNI and we will validate
		// we get a certificate for this name.  The outer SNI will
		// be set based on the ECH config.
		ServerName: host,
	}
}
