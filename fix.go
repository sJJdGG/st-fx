package task

import (
	"crypto/tls"
	"crypto/x509"
	"strings"

	"github.com/xtls/xray-core/common/net"
)

var globalSessionCache = tls.NewLRUClientSessionCache(256)

// GetTLSConfig converts this Config into tls.Config.
func GetTLSConfig(opts ...Option) (*tls.Config, error) {
	root, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		ClientSessionCache:     globalSessionCache,
		RootCAs:                root,
		InsecureSkipVerify:     false,
		SessionTicketsDisabled: false,
	}

	for _, opt := range opts {
		opt(config)
	}

	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"} // ?
	}

	// switch TLSMinVersion {
	// case "1.0":
	// 	config.MinVersion = tls.VersionTLS10
	// case "1.1":
	// 	config.MinVersion = tls.VersionTLS11
	// case "1.2":
	// 	config.MinVersion = tls.VersionTLS12
	// case "1.3":
	// 	config.MinVersion = tls.VersionTLS13
	// }

	// switch TLSMaxVersion {
	// case "1.0":
	// 	config.MaxVersion = tls.VersionTLS10
	// case "1.1":
	// 	config.MaxVersion = tls.VersionTLS11
	// case "1.2":
	// 	config.MaxVersion = tls.VersionTLS12
	// case "1.3":
	// 	config.MaxVersion = tls.VersionTLS13
	// }

	if len(c.CipherSuites) > 0 {
		id := make(map[string]uint16)
		for _, s := range tls.CipherSuites() {
			id[s.Name] = s.ID
		}
		for _, n := range strings.Split(c.CipherSuites, ":") {
			if id[n] != 0 {
				config.CipherSuites = append(config.CipherSuites, id[n])
			}
		}
	}

	config.PreferServerCipherSuites = c.PreferServerCipherSuites

	return config, nil
}

// Option for building TLS config.
type Option func(*tls.Config)

// WithDestination sets the server name in TLS config.
func WithDestination(dest net.Destination) Option {
	return func(config *tls.Config) {
		if dest.Address.Family().IsDomain() && config.ServerName == "" {
			config.ServerName = dest.Address.Domain()
		}
	}
}

// WithNextProto sets the ALPN values in TLS config.
func WithNextProto(protocol ...string) Option {
	return func(config *tls.Config) {
		if len(config.NextProtos) == 0 {
			config.NextProtos = protocol
		}
	}
}
