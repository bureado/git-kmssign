package azuresign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

func ecdsaLeafCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	return testLeafCert(t, &key.PublicKey)
}

// fakeClient records the parameters of the last Sign call and returns a canned
// result, so algorithm selection can be verified without a live Key Vault.
type fakeClient struct {
	lastAlgorithm azkeys.SignatureAlgorithm
	lastValue     []byte
	result        []byte
}

func (f *fakeClient) Sign(_ context.Context, _ string, _ string, params azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	if params.Algorithm != nil {
		f.lastAlgorithm = *params.Algorithm
	}
	f.lastValue = params.Value
	result := f.result
	if result == nil {
		result = []byte("signature")
	}
	resp := azkeys.SignResponse{}
	resp.Result = result
	return resp, nil
}

func testLeafCert(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()

	// Self-sign with a throwaway key; only the embedded public key matters here.
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signingKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func newRSASigner(t *testing.T, client keyVaultClient) (*Signer, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	cert := testLeafCert(t, &key.PublicKey)
	signer, err := NewSigner(client, "my-key", "", cert)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer, &key.PublicKey
}

func TestSignPKCS1v15UsesRS256(t *testing.T) {
	fc := &fakeClient{}
	signer, _ := newRSASigner(t, fc)

	digest := sha256.Sum256([]byte("hello"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if fc.lastAlgorithm != azkeys.SignatureAlgorithmRS256 {
		t.Errorf("algorithm = %q, want RS256", fc.lastAlgorithm)
	}
}

func TestSignPSSUsesPS256(t *testing.T) {
	fc := &fakeClient{}
	signer, _ := newRSASigner(t, fc)

	digest := sha256.Sum256([]byte("hello"))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	if _, err := signer.Sign(rand.Reader, digest[:], opts); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if fc.lastAlgorithm != azkeys.SignatureAlgorithmPS256 {
		t.Errorf("algorithm = %q, want PS256 (PSS must not be downgraded)", fc.lastAlgorithm)
	}
}

func TestSignRejectsNonSHA256(t *testing.T) {
	fc := &fakeClient{}
	signer, _ := newRSASigner(t, fc)

	// A SHA-512-sized digest with a SHA-512 opts must be rejected.
	digest := make([]byte, 64)
	if _, err := signer.Sign(rand.Reader, digest, crypto.SHA512); err != ErrUnsupportedHash {
		t.Errorf("err = %v, want ErrUnsupportedHash", err)
	}
	if fc.lastValue != nil {
		t.Errorf("Key Vault should not have been called for an unsupported hash")
	}
}

func TestSignRejectsPSSWithNonSHA256(t *testing.T) {
	fc := &fakeClient{}
	signer, _ := newRSASigner(t, fc)

	digest := sha256.Sum256([]byte("hello"))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384}
	if _, err := signer.Sign(rand.Reader, digest[:], opts); err != ErrUnsupportedHash {
		t.Errorf("err = %v, want ErrUnsupportedHash", err)
	}
}

func TestSignRejectsWrongDigestLength(t *testing.T) {
	fc := &fakeClient{}
	signer, _ := newRSASigner(t, fc)

	if _, err := signer.Sign(rand.Reader, []byte("short"), crypto.SHA256); err == nil {
		t.Error("expected error for wrong digest length, got nil")
	}
}

func TestNewSignerRejectsNonRSA(t *testing.T) {
	// Build a certificate carrying an ECDSA public key and confirm rejection.
	ecCert := ecdsaLeafCert(t)
	if _, err := NewSigner(&fakeClient{}, "my-key", "", ecCert); err != ErrUnsupportedKey {
		t.Errorf("err = %v, want ErrUnsupportedKey", err)
	}
}

func TestPublicMatchesLeaf(t *testing.T) {
	fc := &fakeClient{}
	signer, want := newRSASigner(t, fc)
	got, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() type = %T, want *rsa.PublicKey", signer.Public())
	}
	if got.N.Cmp(want.N) != 0 || got.E != want.E {
		t.Error("Public() does not match the leaf certificate's key")
	}
}
