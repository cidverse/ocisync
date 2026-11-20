package ocisync

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

const (
	// dialTimeout limits establishing a tcp connection.
	dialTimeout = 30 * time.Second
	// tlsHandshakeTimeout limits the tls handshake.
	tlsHandshakeTimeout = 15 * time.Second
	// responseHeaderTimeout limits waiting for a server to start responding to a request, so an unresponsive
	// server can't hang the sync. it does not limit the body transfer, so large layers are unaffected.
	responseHeaderTimeout = 2 * time.Minute
	// helmRequestTimeout limits a complete helm repository request (index.yaml or chart download), including the body.
	helmRequestTimeout = 10 * time.Minute
)

// newHTTPTransport returns a transport with connect, handshake and response header timeouts.
func newHTTPTransport(insecureSkipVerify bool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = tlsHandshakeTimeout
	transport.ResponseHeaderTimeout = responseHeaderTimeout
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // opt-in via the insecure registry option
	}
	return transport
}
