package certstore

import (
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/bureado/git-kmssign/azuresign"
)

// On Linux there is no local certificate store to talk to. Instead, the store
// is backed by Azure Key Vault: the private key lives in Key Vault and the
// public certificate is loaded from the PEM file named by GIT_KMSSIGN_CERT.
// This is what lets git-kmssign work on Linux, where upstream smimesign
// intentionally does not build.
func openStore() (Store, error) {
	return &kmsStore{}, nil
}

// kmsStore is an Azure Key Vault-backed implementation of Store.
type kmsStore struct{}

// Identities loads the single Key Vault-backed identity described by the
// GIT_KMSSIGN_* environment variables.
func (s *kmsStore) Identities() ([]Identity, error) {
	cfg, err := azuresign.LoadConfig()
	if err != nil {
		return nil, err
	}

	id, err := azuresign.NewIdentity(cfg)
	if err != nil {
		return nil, err
	}

	return []Identity{&kmsIdentity{id: id}}, nil
}

// Import is not supported: the private key is managed in Azure Key Vault.
func (s *kmsStore) Import(data []byte, password string) error {
	return errors.New("certstore: Import is not supported by the Azure Key Vault backend")
}

// Close is a no-op for the Key Vault-backed store.
func (s *kmsStore) Close() {}

// kmsIdentity adapts an azuresign.Identity to the certstore.Identity interface.
type kmsIdentity struct {
	id *azuresign.Identity
}

// Certificate returns the leaf (signing) certificate.
func (i *kmsIdentity) Certificate() (*x509.Certificate, error) {
	return i.id.Leaf(), nil
}

// CertificateChain returns the full certificate chain loaded from the PEM file.
func (i *kmsIdentity) CertificateChain() ([]*x509.Certificate, error) {
	return i.id.Chain(), nil
}

// Signer returns the Azure Key Vault-backed crypto.Signer.
func (i *kmsIdentity) Signer() (crypto.Signer, error) {
	return i.id.Signer, nil
}

// Delete is not supported: the key is managed in Azure Key Vault.
func (i *kmsIdentity) Delete() error {
	return errors.New("certstore: Delete is not supported by the Azure Key Vault backend")
}

// Close is a no-op for the Key Vault-backed identity.
func (i *kmsIdentity) Close() {}
