package azuresign

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadCertificates reads a PEM file and returns every X.509 certificate found
// in it, in file order. The first certificate is expected to be the leaf
// (signing) certificate; any remaining certificates are treated as the chain.
func LoadCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("azuresign: failed to read certificate file %q: %w", path, err)
	}

	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("azuresign: failed to parse certificate in %q: %w", path, err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("azuresign: no PEM certificates found in %q", path)
	}

	return certs, nil
}
