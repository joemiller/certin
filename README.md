certin
=======

![ci-cd](https://github.com/joemiller/certin/workflows/main/badge.svg)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](http://godoc.org/github.com/joemiller/certin)

Certin is a Go library and CLI for quickly creating keys and certificates for use
as test fixtures.

It is available as both a Go library for use in Go tests as well as a CLI for
creating fixtures as files for Go or any other language.

CLI
---

### Install

Available options:

* `go get -u github.com/joemiller/certin/cmd/certin`
* macOS homebrew (Linuxbrew might work too): `brew install joemiller/taps/certin`
* Binaries for all platforms (macOS, Linux, *BSD) on [GitHub Releases](https://github.com/joemiller/certin/releases)
* [Docker images](https://hub.docker.com/r/joemiller/certin)

Usage:

```console
$ certin create KEY CERT
Flags:
      --bundle string        (optional) Create combined bundle FILE containing private-key, certificate, and signing CA cert
      --cn string            common name
  -d, --duration string      certificate duration. Examples of valid values: 1w, 1d, 2d3h5m, 1h30m, 10s (default "1y")
  -h, --help                 help for create
      --is-ca                create a CA cert capable of signing other certs
  -K, --key-type string      key type to create (rsa-2048, rsa-3072, rsa-4096, ecdsa-256, ecdsa-384, ecdsa-512, ed25519) (default "rsa-2048")
      --o strings            organization
      --ou strings           organizational unit
      --sans strings         SubjectAltNames, comma separated
  -c, --signer-cert string   CA cert to sign the CERT with. If omitted, a self-signed cert is generated.
  -k, --signer-key string    CA key to sign the CERT with. If omitted, a self-signed cert is generated.
```

Examples:

* self-signed cert:

```console
certin create self-signed.key self-signed.crt
```

* root CA:

```console
certin create root.key root.crt --is-ca=true
```

* intermediate CA:

```console
certin create intermediate.key intermediate.crt \
  --signer-key root.key \
  --signer-crt root.crt \
  --is-ca
```

* leaf cert with SubjectAltNames (SANs):

```console
certin create example.key example.crt \
  --signer-key intermediate.key \
  --signer-crt intermediate.crt \
  --cn example.com \
  --sans "example.com,www.example.com" \
  --key-type "ecdsa-256"
```

Go Library
----------

```
go get -u github.com/joemiller/certin
```

Example uses:

```go
// See certin.go or the godoc page for details on each struct member
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
```

* simple self-signed cert:

```go
// the first param to NewCert is the parent (signing) CA cert. nil creates a self-signed cert
// the returned value is a certin.KeyAndCert
root, err := certin.NewCert(nil, certin.Request{CN: "self-signed"}))
```

* root CA cert:

```go
root, err := certin.NewCert(nil, certin.Request{CN: "root CA", IsCA: true}))
```

* root and intermediate CA certs:

```go
root, err := certin.NewCert(nil, Request{CN: "root", IsCA: true})
// pass the root key/cert to NewCert() to sign the intermediate cert
interm, err := certin.NewCert(root, Request{CN: " intermediate", IsCA: true})
```

* leaf certificate signed by intermediate:

```go
leaf, err := certin.NewCert(interm, Request{CN: "example.com", SANs: []string{"example.com", "www.example.com"}})
```

If you need more control over the contents of the certificate you can create a cert
from a `x509.Certificate` template instead of `certin.Request`. This allows for full
  control over the contents of the cert.

```go
templ := &x509.Certificate{
  SerialNumber: big.NewInt(123456789),
  Subject: pkix.Name{
    Organization:       []string{"My Org"},
    OrganizationalUnit: []string{"My dept"},
    CommonName:         "example.com",
  },
  DNSNames: []string{"example.com"}

  NotBefore: time.Now(),
  NotAfter:  time.Now().Add(10 * time.Minute),
	KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
}
cert, err := certin.NewCertFromX509Template(interm, "ecdsa-256", templ)
```

Motivation
----------

I've worked on lots of projects that involved TLS certs and found myself constantly
needing to create certificate hiearchies for test fixtures. There are plenty of great
tools that can accomplish this. After experimenting with a few of them I decided I
wanted something simpler and built specifically for the simplest test cases.

- `openssl`: Plenty capable of being scripted to create root and intermediate CAs and
  sign certs. However you usually end up with some mixture of openssl.cnf file to
  express certain options in combination with command line flags.
- `cfssl`: Very flexible, easy to install and use. Most config is done through JSON
  files.

I felt like the common cases for certs needed during testing should be generatable
with a simple CLI and only a few command flags and common defaults, no config files or
complex scripts.

TODO
----

support CSRs:

```go
cert, err := NewCertFromCSR(root, crypto.PrivateKey, x509.CertificateRequest{})
```

```console
certin sign ...
```
