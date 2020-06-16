certin
=======

TODO

------------------------------------------------------------------------------

TODO
====

API

* simple self-signed cert

```go
// the first param to NewCert is the parent (signing) CA cert. nil creates a self-signed cert
root, err := certin.NewCert(nil, certin.Request{CN: "self-signed"}))
```

* root CA cert

```go
root, err := certin.NewCert(nil, certin.Request{CN: "root CA", IsCA: true}))
```

* root and intermediate CA certs

```go
root, err := NewCert(nil, Request{CN: "root", IsCA: true})
// pass the root key/cert to NewCert() to sign the intermediate cert
interm, err := NewCert(root, Request{CN: " intermediate", IsCA: true})
```

* yubikey attestation cert chain example
```go
root, err := NewCert(nil, Request{CN: "yubico root", IsCA: true})
interm, err := NewCert(root, Request{CN: "yubikey attestation intermediate", IsCA: true})
yubikeyAttestationCert, err := NewCertFromX509Template(interm, *x509.Certificate{.... all the details in a yubikey attestation cert ...})
```