package azuresign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigRequiresVars(t *testing.T) {
	for _, v := range []string{EnvVaultURL, EnvKeyName, EnvKeyVersion, EnvCertPath} {
		t.Setenv(v, "")
	}
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error when required vars are unset")
	}

	t.Setenv(EnvVaultURL, "https://v.vault.azure.net/")
	t.Setenv(EnvKeyName, "k")
	t.Setenv(EnvCertPath, "/tmp/c.pem")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.VaultURL == "" || cfg.KeyName == "" || cfg.CertPath == "" {
		t.Errorf("config not populated: %+v", cfg)
	}
	if cfg.KeyVersion != "" {
		t.Errorf("KeyVersion = %q, want empty", cfg.KeyVersion)
	}
}

func writeTestCertPEM(t *testing.T, dir string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	path := filepath.Join(dir, "cert.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode pem: %v", err)
	}
	return path
}

func TestLoadCertificates(t *testing.T) {
	dir := t.TempDir()
	path := writeTestCertPEM(t, dir)

	certs, err := LoadCertificates(path)
	if err != nil {
		t.Fatalf("LoadCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "leaf" {
		t.Errorf("CN = %q, want leaf", certs[0].Subject.CommonName)
	}
}

func TestLoadCertificatesErrors(t *testing.T) {
	if _, err := LoadCertificates(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("expected error for missing file")
	}

	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadCertificates(empty); err == nil {
		t.Error("expected error for file with no certificates")
	}
}
