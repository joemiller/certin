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

// Request is a simplified configuration for generating a keypair and certificate
// with the NewCert() func. The most common attributes for a keypair and cert are
// available but if you need more control over the certificate contents you should
// create a x509.Certificate template and use the NewCertFromX509Template() func
// instead.
type Request struct {
	// CommonName to use in the certificate Subject
	CN string

	// Organization(s) to include in the Subject
	O []string

	// Organizationl Units(s) to include in the Subject
	OU []string

	// SANs is a list of SubjectAltNames to include in the certificate. DNS, IP, Email, and URIs are
	// supported.
	SANs []string

	// Certiicate duration. Default is 1 year if not specified
	Duration time.Duration

	// IsCA will create a CA certificate that can be used to sign other certificates.
	IsCA bool

	// KeyType is the type of private/public key pair to create. Supported keytypes
	// are:
	//   rsa-2048, rsa-3072, rsa-4096
	//   ecdsa-224, ecdsa-256, ecdsa-384, ecdsa-521
	//   ed25519
	KeyType string
}

// KeyAndCert represents a bundle of private, public keys and an associated Certificate
type KeyAndCert struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
	PublicKey   crypto.PublicKey
}

// NewCert creates a new keypair and certificate from a Request object. If parent is
// nil it will be a self-signed certificate, otherwise it will be signed by the private
// key and certificate in the parent object.
func NewCert(parent *KeyAndCert, req Request) (*KeyAndCert, error) {
	if req.KeyType == "" {
		req.KeyType = DefaultKeyType
	}
	priv, err := GenerateKey(req.KeyType)
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

	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if req.IsCA {
		keyUsage = x509.KeyUsageCertSign
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

		KeyUsage: keyUsage,

		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
		MaxPathLenZero:        req.IsCA,
	}

	// Add SANs. Supported types: IPaddr, email, URIs, DNSnames
	addSans(self, req.SANs)

	// for non-CA certs add the common name to the list of SANs since modern browsers
	// are phasing out common name.
	// TODO: fix this for the case of non-DNSName in CN such as email addr.
	if len(self.DNSNames) == 0 && !req.IsCA {
		self.DNSNames = append(self.DNSNames, req.CN)
	}

	if !req.IsCA {
		self.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		if len(self.EmailAddresses) > 0 {
			self.ExtKeyUsage = append(self.ExtKeyUsage, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection)
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

// NewCertFromX509Template creates a new keypair and certificate from an X509.Certificate template.
// If parent is nil, it will be self-signed, otherwise it will be signed by the private key
// and cert from the parent.
func NewCertFromX509Template(parent *KeyAndCert, keyType string, templ *x509.Certificate) (*KeyAndCert, error) {
	if keyType == "" {
		keyType = DefaultKeyType
	}
	priv, err := GenerateKey(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	pub := priv.(crypto.Signer).Public()

	// generate a random serial number if the template did not provide one. Go won't sign a cert without a serial
	if templ.SerialNumber == nil {
		serial, err := randomSerialNumber()
		if err != nil {
			return nil, err
		}
		templ.SerialNumber = serial
	}

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

// GenerateKey generates a private/public key pair. Valid keytypes are:
//   rsa-2048, rsa-3072, rsa-4096
//   ecdsa-224, ecdsa-256, ecdsa-384, ecdsa-521
//   ed25519
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

// Export saves a private key and certficate from a KeyAndCert to keyFile and certFile.
func Export(keyFile, certFile string, cert *KeyAndCert) error {
	if err := ExportPrivateKey(keyFile, cert.PrivateKey); err != nil {
		return err
	}
	if err := ExportCert(certFile, cert.Certificate); err != nil {
		return err
	}
	return nil
}

// ExportPrivateKey saves a private key in PEM format from a KeyAndCert to file.
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

// ExportPublicKey saves a public key in PEM format from a KeyAndCert to file.
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

// ExportCert saves a certificate in PEM format from a KeyAndCert to file.
func ExportCert(file string, cert *x509.Certificate) error {
	return ioutil.WriteFile(
		file,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		0600)
}

// LoadKeyAndCert loads and parses a private key and certificate from keyFile and
// certFile and returns a KeyAndCert.
func LoadKeyAndCert(keyFile string, certFile string) (*KeyAndCert, error) {
	key, err := LoadKey(keyFile)
	if err != nil {
		return nil, err
	}
	cert, err := LoadCert(certFile)
	if err != nil {
		return nil, err
	}

	return &KeyAndCert{
		Certificate: cert,
		PrivateKey:  key,
		PublicKey:   key.(crypto.Signer).Public(),
	}, nil
}

// LoadCert loads and parses a certificate from file and returns a *x509.Certificate.
func LoadCert(file string) (*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	der, _ := pem.Decode(pemBytes)
	if der == nil {
		return nil, fmt.Errorf("failed to parse certificate: %s", file)
	}
	return x509.ParseCertificate(der.Bytes)
}

// LoadKey loads and parses a private key from file and returns a crypto.PrivateKey.
func LoadKey(file string) (crypto.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	der, _ := pem.Decode(pemBytes)
	if der == nil {
		return nil, fmt.Errorf("failed to parse key: %s", file)
	}

	if key, err := x509.ParsePKCS1PrivateKey(der.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		case ed25519.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("Failed to parse private key")
}

// addSans parses a slice of SANs and adds them to the cert.
// Supported types: IPaddr, email, URIs, DNSnames
func addSans(cert *x509.Certificate, sans []string) {
	for _, h := range sans {
		if ip := net.ParseIP(h); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			cert.EmailAddresses = append(cert.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			cert.URIs = append(cert.URIs, uriName)
		} else {
			cert.DNSNames = append(cert.DNSNames, h)
		}
	}
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
