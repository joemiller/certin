package certin_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joemiller/certin"
	"github.com/stretchr/testify/assert"
)

func TestNewCert_RootCA(t *testing.T) {
	req := certin.Request{
		CN:      "root CA",
		IsCA:    true,
		KeyType: "rsa-3072",
	}

	cert, err := certin.NewCert(nil, req)
	assert.Nil(t, err)

	// verify cert attributes
	assert.Equal(t, "root CA", cert.Certificate.Subject.CommonName)
	assert.Equal(t, true, cert.Certificate.BasicConstraintsValid)
	assert.Equal(t, true, cert.Certificate.IsCA)
	assert.Equal(t, true, cert.Certificate.MaxPathLenZero)

	// verify key
	assert.IsType(t, &rsa.PrivateKey{}, cert.PrivateKey)
	assert.Equal(t, 3072, cert.PrivateKey.(*rsa.PrivateKey).N.BitLen())
}

func TestNewCert_Root_and_Intermediate(t *testing.T) {
	root, err := certin.NewCert(nil, certin.Request{CN: "root", IsCA: true})
	assert.Nil(t, err)

	interm, err := certin.NewCert(root, certin.Request{CN: "intermediate", IsCA: true})
	assert.Nil(t, err)

	assert.Equal(t, "root", root.Certificate.Subject.CommonName)
	assert.Equal(t, "root", root.Certificate.Issuer.CommonName)

	assert.Equal(t, "intermediate", interm.Certificate.Subject.CommonName)
	assert.Equal(t, "root", interm.Certificate.Issuer.CommonName)
}

func TestNewCert_Root_Intermediate_and_Leaf(t *testing.T) {
	root, err := certin.NewCert(nil, certin.Request{CN: "root", IsCA: true})
	assert.Nil(t, err)

	interm, err := certin.NewCert(root, certin.Request{CN: "intermediate", IsCA: true})
	assert.Nil(t, err)

	leaf, err := certin.NewCert(interm, certin.Request{CN: "example.com"})
	assert.Nil(t, err)

	assert.Equal(t, "root", root.Certificate.Subject.CommonName)
	assert.Equal(t, "root", root.Certificate.Issuer.CommonName)

	assert.Equal(t, "intermediate", interm.Certificate.Subject.CommonName)
	assert.Equal(t, "root", interm.Certificate.Issuer.CommonName)

	assert.Equal(t, "example.com", leaf.Certificate.Subject.CommonName)
	assert.Equal(t, "intermediate", leaf.Certificate.Issuer.CommonName)
	assert.Contains(t, leaf.Certificate.DNSNames, "example.com")
}

func TestKeyUsage(t *testing.T) {
	root, err := certin.NewCert(nil, certin.Request{CN: "root", IsCA: true})
	assert.Nil(t, err)

	leaf, err := certin.NewCert(root, certin.Request{CN: "example.com"})
	assert.Nil(t, err)

	// CA certs should have the Cert Signing Key usage
	assert.Equal(t, x509.KeyUsageCertSign, root.Certificate.KeyUsage)

	// leaf certs should have encrypt and sign usages
	assert.Equal(t, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, leaf.Certificate.KeyUsage)
}

func TestExtKeyUsage(t *testing.T) {
	root, err := certin.NewCert(nil, certin.Request{CN: "root", IsCA: true})
	assert.Nil(t, err)

	sans := []string{"email@example.com"}
	leaf, err := certin.NewCert(root, certin.Request{CN: "example.com", SANs: sans})
	assert.Nil(t, err)

	assert.Empty(t, root.Certificate.ExtKeyUsage)

	assert.Contains(t, leaf.Certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	assert.Contains(t, leaf.Certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, leaf.Certificate.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	assert.Contains(t, leaf.Certificate.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
}

func TestNewCert_SANs(t *testing.T) {
	req := certin.Request{
		CN: "example.com",
		SANs: []string{
			"example.com", // DNSnames
			"www.example.com",
			"127.0.0.1", // IPAddrs
			"2001::db8:1",
			"test@domain.com",         // email addr
			"https://example.com/uri", // uri
		},
	}
	cert, err := certin.NewCert(nil, req)
	assert.Nil(t, err)

	// IP addrs:
	// IP byte arrays can be 4 or 16 in length, so we have to test each individual using net.IP.String()
	assert.Equal(t, "127.0.0.1", cert.Certificate.IPAddresses[0].String())
	assert.Equal(t, "2001::db8:1", cert.Certificate.IPAddresses[1].String())

	// email addrs:
	assert.Contains(t, cert.Certificate.EmailAddresses, "test@domain.com")

	// URIs:
	uri, _ := url.Parse("https://example.com/uri")
	assert.Contains(t, cert.Certificate.URIs, uri)

	// DNS names:
	expectedDNS := []string{"example.com", "www.example.com"}
	assert.ElementsMatch(t, cert.Certificate.DNSNames, expectedDNS)
}

func TestNewCertFromX509Template_RootCA(t *testing.T) {
	templ := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			Organization:       []string{"My Org"},
			OrganizationalUnit: []string{"My dept"},
			CommonName:         "root",
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * time.Minute),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	cert, err := certin.NewCertFromX509Template(nil, "rsa-2048", templ)
	assert.Nil(t, err)

	// verify cert attributes
	assert.Equal(t, "root", cert.Certificate.Subject.CommonName)
	assert.Equal(t, true, cert.Certificate.BasicConstraintsValid)
	assert.Equal(t, true, cert.Certificate.IsCA)
	assert.Equal(t, true, cert.Certificate.MaxPathLenZero)

	// verify key (DeafultKeyType)
	assert.IsType(t, &rsa.PrivateKey{}, cert.PrivateKey)
	assert.Equal(t, 2048, cert.PrivateKey.(*rsa.PrivateKey).N.BitLen())
}

func TestGenerateKey_RSA(t *testing.T) {
	tests := []struct {
		keytype      string
		expectedBits int
		shouldErr    bool
	}{
		{
			keytype:      "rsa-2048",
			expectedBits: 2048,
			shouldErr:    false,
		},
		{
			keytype:      "rsa-3072",
			expectedBits: 3072,
			shouldErr:    false,
		},
		{
			keytype:      "rsa-4096",
			expectedBits: 4096,
			shouldErr:    false,
		},
		{
			keytype:   "rsa-14096",
			shouldErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.keytype, func(t *testing.T) {
			key, err := certin.GenerateKey(tc.keytype)

			if tc.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if key != nil {
				assert.IsType(t, &rsa.PrivateKey{}, key)
				assert.Equal(t, tc.expectedBits, key.(*rsa.PrivateKey).N.BitLen())
			}
		})
	}
}

func TestGenerateKey_ECDSA(t *testing.T) {
	tests := []struct {
		keytype       string
		expectedCurve elliptic.Curve
		shouldErr     bool
	}{
		{
			keytype:       "ecdsa-224",
			expectedCurve: elliptic.P224(),
			shouldErr:     false,
		},
		{
			keytype:       "ecdsa-256",
			expectedCurve: elliptic.P256(),
			shouldErr:     false,
		},
		{
			keytype:       "ecdsa-384",
			expectedCurve: elliptic.P384(),
			shouldErr:     false,
		},
		{
			keytype:       "ecdsa-521",
			expectedCurve: elliptic.P521(),
			shouldErr:     false,
		},
		{
			keytype:   "ecdsa-9999",
			shouldErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.keytype, func(t *testing.T) {
			key, err := certin.GenerateKey(tc.keytype)

			if tc.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if key != nil {
				assert.IsType(t, &ecdsa.PrivateKey{}, key)
				assert.IsType(t, tc.expectedCurve, key.(*ecdsa.PrivateKey).Curve)
			}
		})
	}
}

func TestGenerateKey_ed25519(t *testing.T) {
	tests := []struct {
		keytype   string
		shouldErr bool
	}{
		{
			keytype:   "ed25519",
			shouldErr: false,
		},
		{
			keytype:   "foo-ed25519-123",
			shouldErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.keytype, func(t *testing.T) {
			key, err := certin.GenerateKey(tc.keytype)

			if tc.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if key != nil {
				assert.IsType(t, ed25519.PrivateKey{}, key)
			}
		})
	}
}

func TestExportAndLoad(t *testing.T) {
	// TODO: go 1.15+, replace with the new TB.TempDir()
	tempDir, cleanup := tempDir(t)
	defer cleanup()

	algos := []string{"rsa-2048", "ecdsa-256", "ed25519"}

	for _, algo := range algos {
		t.Log(algo)
		keyFile := filepath.Join(tempDir, "test.key")
		certFile := filepath.Join(tempDir, "test.crt")

		cert, err := certin.NewCert(nil, certin.Request{KeyType: algo})
		assert.NoError(t, err)

		err = certin.Export(keyFile, certFile, cert)
		assert.NoError(t, err)

		loadedCert, err := certin.LoadKeyAndCert(keyFile, certFile)
		assert.NoError(t, err)
		assert.Equal(t, cert, loadedCert, "generated cert and cert loaded from disk are not equal")
	}
}

func tempDir(t *testing.T) (string, func()) {
	tempDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	cleanup := func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Errorf("TempDir RemoveAll cleanup: %v", err)
		}
	}
	return tempDir, cleanup
}
