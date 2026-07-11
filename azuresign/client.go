package azuresign

import (
	"crypto/x509"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// Identity bundles the Key Vault-backed Signer with the certificate and chain
// loaded from the configured PEM file.
type Identity struct {
	// Signer performs private-key operations via Azure Key Vault.
	Signer *Signer

	// Certs holds every certificate from the PEM file, leaf first.
	Certs []*x509.Certificate
}

// Leaf returns the leaf (signing) certificate.
func (id *Identity) Leaf() *x509.Certificate {
	return id.Certs[0]
}

// Chain returns the full certificate chain (leaf plus any intermediates).
func (id *Identity) Chain() []*x509.Certificate {
	return id.Certs
}

// NewIdentity builds an Identity from Config. It authenticates using
// azidentity.DefaultAzureCredential, which prefers a service-principal client
// secret from the AZURE_* environment variables (useful for local testing) and
// otherwise falls back to a system- or user-assigned managed identity.
func NewIdentity(cfg *Config) (*Identity, error) {
	certs, err := LoadCertificates(cfg.CertPath)
	if err != nil {
		return nil, err
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azuresign: failed to obtain Azure credential: %w", err)
	}

	client, err := azkeys.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azuresign: failed to create Key Vault client: %w", err)
	}

	signer, err := NewSigner(client, cfg.KeyName, cfg.KeyVersion, certs[0])
	if err != nil {
		return nil, err
	}

	return &Identity{Signer: signer, Certs: certs}, nil
}
