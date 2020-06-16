package certin_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/joemiller/certin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFooTODOPlayground(t *testing.T) {
	// root, err := certin.NewCert(nil, "root", true, "rsa-3072")
	root, err := certin.NewCert(nil,
		certin.Request{CN: "root",
			IsCA:    true,
			KeyType: "rsa-3072",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("root issuer: ", root.Certificate.Issuer)
	t.Log("root subject: ", root.Certificate.Subject)
	t.Log("root isCA: ", root.Certificate.IsCA)

	// interm, err := certin.NewCert(root, "intermediate", true, "ecdsa-256")
	interm, err := certin.NewCert(root, certin.Request{CN: "intermediate", IsCA: true, KeyType: "ecdsa-256"})
	require.NoError(t, err)
	t.Log("intm issuer: ", interm.Certificate.Issuer)
	t.Log("intm subject: ", interm.Certificate.Subject)
	t.Log("intm isCA: ", interm.Certificate.IsCA)

	if err := certin.Export("root.key", "root.crt", root); err != nil {
		require.NoError(t, err)
	}

	// leaf, err := certin.NewCert(interm, "www.example.com", false, "ed25519")
	leaf, err := certin.NewCert(interm, certin.Request{CN: "example.com", KeyType: "ed25519"})
	require.NoError(t, err)
	t.Log("leaf issuer: ", leaf.Certificate.Issuer)
	t.Log("leaf subject: ", leaf.Certificate.Subject)
	t.Log("leaf isCA: ", leaf.Certificate.IsCA)

	if err := certin.Export("leaf.key", "leaf.crt", leaf); err != nil {
		t.Fatal(err)
	}
	// spew.Dump(root)
}

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
	// TODO: check expiration, subjectKeyId

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

func TestNewCert_SANs(t *testing.T) {
	req := certin.Request{
		CN: "example.com",
		SANs: []string{
			"example.com", // DNSname
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
	cert, err := certin.NewCertFromX509Template(nil, templ)
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

// TODO: test Export() (save then read keys/certs)
