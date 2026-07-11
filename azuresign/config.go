// Package azuresign provides a crypto.Signer backed by Azure Key Vault. It
// replaces smimesign's local private-key signer while leaving certificate
// discovery, CMS construction, the Git protocol, and verification untouched.
package azuresign

import (
	"fmt"
	"os"
)

// Environment variables used to configure the Azure Key Vault signer. Key
// selection and the certificate location are passed via these variables rather
// than being encoded into git's user.signingKey.
const (
	// EnvVaultURL is the Key Vault base URL, e.g.
	// "https://myvault.vault.azure.net/".
	EnvVaultURL = "GIT_KMSSIGN_VAULT_URL"

	// EnvKeyName is the name of the signing key in Key Vault.
	EnvKeyName = "GIT_KMSSIGN_KEY_NAME"

	// EnvKeyVersion optionally pins a key version. Empty means "latest".
	EnvKeyVersion = "GIT_KMSSIGN_KEY_VERSION"

	// EnvCertPath is the path to a PEM file holding the public X.509
	// certificate (leaf first, optional intermediates). The private key stays
	// in Key Vault; the certificate is required for CMS construction and
	// verification.
	EnvCertPath = "GIT_KMSSIGN_CERT"
)

// Config holds the resolved Azure Key Vault signer configuration.
//
// Client authentication material (managed identity by default, or a service
// principal client secret for local testing) is not part of Config: it is read
// directly from the standard AZURE_* environment variables by
// azidentity.DefaultAzureCredential.
type Config struct {
	// VaultURL is the Key Vault base URL.
	VaultURL string

	// KeyName is the Key Vault key name to sign with.
	KeyName string

	// KeyVersion optionally pins a key version. Empty means "latest".
	KeyVersion string

	// CertPath is the path to the PEM certificate file.
	CertPath string
}

// LoadConfig reads the GIT_KMSSIGN_* environment variables and validates that
// the required ones are present.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		VaultURL:   os.Getenv(EnvVaultURL),
		KeyName:    os.Getenv(EnvKeyName),
		KeyVersion: os.Getenv(EnvKeyVersion),
		CertPath:   os.Getenv(EnvCertPath),
	}

	var missing []string
	if cfg.VaultURL == "" {
		missing = append(missing, EnvVaultURL)
	}
	if cfg.KeyName == "" {
		missing = append(missing, EnvKeyName)
	}
	if cfg.CertPath == "" {
		missing = append(missing, EnvCertPath)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("azuresign: missing required environment variable(s): %v", missing)
	}

	return cfg, nil
}
