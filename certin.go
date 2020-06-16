package certin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"time"
)

var (
	DefaultKeyType  = "rsa-2048"
	DefaultDuration = 365 * 24 * time.Hour
)

type Request struct {
	CN       string
	O        []string
	OU       []string
	SANs     []string
	Duration time.Duration
	IsCA     bool
	KeyType  string
}

type KeyAndCert struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
	PublicKey   crypto.PublicKey
}

func NewCert(parent *KeyAndCert, req Request) (*KeyAndCert, error) {
	keytype := DefaultKeyType
	if req.KeyType != "" {
		keytype = req.KeyType
	}
	priv, err := GenerateKey(keytype)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	pub := priv.(crypto.Signer).Public()

	skid, err := subjectKeyId(pub)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	notBefore := time.Now().Add(-30 * time.Second)
	notAfter := time.Now().Add(req.Duration)
	if req.Duration == 0 {
		notAfter = time.Now().Add(DefaultDuration)
	}

	self := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       req.O,
			OrganizationalUnit: req.OU,
			CommonName:         req.CN,
		},
		SubjectKeyId: skid[:],

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
		MaxPathLenZero:        req.IsCA,
	}

	// Add SANs. Supported types: IPaddr, email, URIs, DNSnames
	for _, h := range req.SANs {
		if ip := net.ParseIP(h); ip != nil {
			self.IPAddresses = append(self.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			self.EmailAddresses = append(self.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			self.URIs = append(self.URIs, uriName)
		} else {
			self.DNSNames = append(self.DNSNames, h)
		}
	}

	// if parent is nil, this will be a self signed cert
	signerCert := self
	if parent != nil {
		signerCert = parent.Certificate
	}
	signerKey := priv
	if parent != nil {
		signerKey = parent.PrivateKey
	}

	// return signKeyAndCert(self, signerCert, pub, signerKey)
	certDER, err := x509.CreateCertificate(rand.Reader, self, signerCert, pub, signerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated cert: %v", err)
	}

	bundle := &KeyAndCert{
		Certificate: cert,
		PrivateKey:  priv,
		PublicKey:   pub,
	}
	return bundle, nil
}

// func NewCertFromX509Template(parent *KeyAndCert, private *crypto.PrivateKey templ *x509.Certificate) (*KeyAndCert, error) {
func NewCertFromX509Template(parent *KeyAndCert, templ *x509.Certificate) (*KeyAndCert, error) {
	priv, err := GenerateKey(DefaultKeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	pub := priv.(crypto.Signer).Public()

	// if parent is nil, this will be a self signed cert
	signerCert := templ
	if parent != nil {
		signerCert = parent.Certificate
	}
	signerKey := priv
	if parent != nil {
		signerKey = parent.PrivateKey
	}

	// return signKeyAndCert(templ, signerCert, pub, signerKey)
	certDER, err := x509.CreateCertificate(rand.Reader, templ, signerCert, pub, signerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated cert: %v", err)
	}

	bundle := &KeyAndCert{
		Certificate: cert,
		PrivateKey:  priv,
		PublicKey:   pub,
	}
	return bundle, nil
}

// func signKeyAndCert(templ *x509.Certificate, signerCert *x509.Certificate, pub crypto.PublicKey, signerKey crypto.PrivateKey) (*KeyAndCert, error) {
// 	certDER, err := x509.CreateCertificate(rand.Reader, templ, signerCert, pub, signerKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to sign cert: %v", err)
// 	}

// 	cert, err := x509.ParseCertificate(certDER)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse generated cert: %v", err)
// 	}

// 	bundle := &KeyAndCert{
// 		Certificate: cert,
// 		PrivateKey:  priv,
// 		PublicKey:   pub,
// 	}
// 	return bundle, nil

// }

// GenerateKey generates a private/public key pair. Valid keytypes are:
// rsa-2048, rsa-3072, rsa-4096
// ecdsa-224, ecdsa-256, ecdsa-384, ecdsa-521
// ed25519
func GenerateKey(keyType string) (crypto.PrivateKey, error) {
	switch keyType {
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	case "ecdsa-224":
		return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "ecdsa-256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ecdsa-521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	return nil, fmt.Errorf("unknown keyType %s", keyType)
}

func Export(keyFile, certFile string, cert *KeyAndCert) error {
	if err := ExportPrivateKey(keyFile, cert.PrivateKey); err != nil {
		return err
	}
	if err := ExportCert(certFile, cert.Certificate); err != nil {
		return err
	}
	return nil
}

func ExportPrivateKey(file string, priv crypto.PrivateKey) error {
	derBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %v", err)
	}
	return ioutil.WriteFile(
		file,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derBytes}),
		0600)
}

func ExportPublicKey(file string, pub crypto.PublicKey) error {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %v", err)
	}
	return ioutil.WriteFile(
		file,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}),
		0600)
}

func ExportCert(file string, cert *x509.Certificate) error {
	err := ioutil.WriteFile(
		file,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		0600)
	if err != nil {
		return err
	}
	return nil
}

func subjectKeyId(pub crypto.PublicKey) ([20]byte, error) {
	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [20]byte{}, fmt.Errorf("failed to marshal public key: %v", err)
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		return [20]byte{}, fmt.Errorf("failed to decode public key: %v", err)
	}

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return skid, nil
}

func randomSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}
	return serialNumber, nil
}
