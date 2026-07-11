package azuresign

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

var (
	// ErrUnsupportedHash is returned when a signature is requested with a hash
	// algorithm other than SHA-256. This POC intentionally supports RSA with
	// SHA-256 only.
	ErrUnsupportedHash = errors.New("azuresign: unsupported hash algorithm (only SHA-256 is supported)")

	// ErrUnsupportedKey is returned when the certificate's public key is not
	// RSA. ECDSA and other key types are not supported.
	ErrUnsupportedKey = errors.New("azuresign: unsupported key type (only RSA is supported)")
)

// defaultSignTimeout bounds a single Key Vault Sign call. crypto.Signer.Sign
// has no context parameter, so we apply a sensible default here.
const defaultSignTimeout = 30 * time.Second

// keyVaultClient is the subset of *azkeys.Client used by Signer. It is an
// interface so the signing logic can be unit-tested without a live Key Vault.
type keyVaultClient interface {
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

// Signer is a crypto.Signer whose private key operations are performed by Azure
// Key Vault. The public key and certificate are held locally so that the CMS
// layer can match signer.Public() against the leaf certificate.
type Signer struct {
	client     keyVaultClient
	keyName    string
	keyVersion string
	pub        *rsa.PublicKey
}

// NewSigner builds a Signer from a Key Vault client, key coordinates, and the
// leaf certificate. The leaf certificate must carry an RSA public key.
func NewSigner(client keyVaultClient, keyName, keyVersion string, leaf *x509.Certificate) (*Signer, error) {
	if client == nil {
		return nil, errors.New("azuresign: nil key vault client")
	}
	if keyName == "" {
		return nil, errors.New("azuresign: empty key name")
	}
	if leaf == nil {
		return nil, errors.New("azuresign: nil leaf certificate")
	}

	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrUnsupportedKey
	}

	return &Signer{
		client:     client,
		keyName:    keyName,
		keyVersion: keyVersion,
		pub:        pub,
	}, nil
}

// Public returns the RSA public key of the leaf certificate. It must exactly
// match the certificate the CMS layer signs with.
func (s *Signer) Public() crypto.PublicKey {
	return s.pub
}

// Sign performs an RSA signature over digest using Azure Key Vault.
//
// Only SHA-256 is supported. If opts is an *rsa.PSSOptions, an RSASSA-PSS
// (PS256) signature is produced; otherwise an RSASSA-PKCS1-v1_5 (RS256)
// signature is produced. A PSS request is never silently downgraded to
// PKCS#1 v1.5.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, ErrUnsupportedHash
	}
	if opts.HashFunc() != crypto.SHA256 {
		return nil, ErrUnsupportedHash
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("azuresign: digest length %d does not match SHA-256 size %d", len(digest), sha256.Size)
	}

	alg := azkeys.SignatureAlgorithmRS256
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		// The caller explicitly asked for RSA-PSS. Honor it as PS256; never
		// translate it into PKCS#1 v1.5.
		if pssOpts.Hash != crypto.SHA256 {
			return nil, ErrUnsupportedHash
		}
		alg = azkeys.SignatureAlgorithmPS256
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSignTimeout)
	defer cancel()

	resp, err := s.client.Sign(ctx, s.keyName, s.keyVersion, azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azuresign: key vault sign failed: %w", err)
	}
	if len(resp.Result) == 0 {
		return nil, errors.New("azuresign: key vault returned an empty signature")
	}

	return resp.Result, nil
}
