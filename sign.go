package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"time"
)

// ErrOptions: the signing request is not one this package will carry out —
// a missing key, a certificate that is not the key's, a combination the RFCs
// forbid. Algorithms it does not implement wrap ErrUnsupported instead, as
// they do when reading.
var ErrOptions = errors.New("cms: invalid signing options")

// ErrSigner: the crypto.Signer failed, or returned a signature that does not
// verify under the signer's certificate (another key, ignored PSS options, an
// empty signature). The signer's own error stays in the chain, so errors.Is
// finds it as well.
var ErrSigner = errors.New("cms: signer failed")

var (
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

// SignOptions says what Sign emits. The zero value, apart from Signer and
// Certificate, is a SignedData over id-data with signed attributes
// (content-type and message-digest), SHA-256, the content ATTACHED.
type SignOptions struct {
	// Signer holds the private key: an *rsa.PrivateKey, an *ecdsa.PrivateKey
	// or an ed25519.PrivateKey, or any crypto.Signer whose Public key is one
	// of those types (a smart card, an HSM, a remote signer).
	Signer crypto.Signer
	// Certificate is the signer's certificate. It is embedded, and the
	// SignerInfo names it by issuer and serial number (RFC 5652 §5.3). Its
	// public key must be Signer's.
	Certificate *x509.Certificate
	// Chain is further certificates to embed (intermediates).
	Chain []*x509.Certificate

	// Hash is the digest: crypto.SHA256 (the default), SHA384 or SHA512.
	// Ed25519 signs with SHA-512 (RFC 8419 §3.1) and refuses any other.
	// SHA-1 is refused by name.
	Hash crypto.Hash
	// PSS selects RSASSA-PSS (MGF1 with Hash, salt as long as the hash)
	// instead of RSASSA-PKCS1-v1_5. RSA keys only.
	PSS bool
	// Rand is the entropy for RSA-PSS and ECDSA; crypto/rand when nil.
	Rand io.Reader

	// ContentType is the eContentType; id-data when nil.
	ContentType asn1.ObjectIdentifier
	// Detached leaves the content out of the container, as a PDF signature
	// does: the verifier is handed the signed bytes (Verify's argument).
	Detached bool

	// NoSignedAttrs signs the content itself, with no signedAttrs — the
	// PKCS#7 shape UEFI authenticated variables use. It needs id-data
	// (§5.3) and excludes SigningTime and SigningCertificateV2, which are
	// attributes.
	NoSignedAttrs bool
	// SigningTime, when not zero, adds the signing-time attribute (§11.3),
	// to the second. PAdES carries the time elsewhere and CAdES leaves it
	// optional, so it is opt-in.
	SigningTime time.Time
	// SigningCertificateV2 adds the signing-certificate-v2 attribute of
	// RFC 5035 §5.4.1, which ETSI CAdES / PAdES baseline signatures require:
	// the hash of the signer's certificate, and its issuer and serial.
	SigningCertificateV2 bool
}

// Sign returns a DER ContentInfo holding a SignedData with ONE signer.
//
// ⛔ What it will not emit: SHA-1 or any digest outside SHA-2 256/384/512;
// RSASSA-PSS parameters other than "this hash, MGF1 with it, salt of its
// length"; Ed25519 with another digest; a certificate whose key is not the
// signer's; a signature that omits the attributes yet claims another content
// type. Everything Sign writes is DER — signedAttrs in particular is a SET OF
// sorted by encoding (§5.4 signs those bytes, and the reader here is strict
// about them) — and every product is meant to pass this package's Verify and
// OpenSSL's `cms -verify`, which the tests assert.
func Sign(content []byte, o SignOptions) ([]byte, error) {
	p, err := o.plan()
	if err != nil {
		return nil, err
	}

	md := p.hash.New()
	md.Write(content)
	contentDigest := md.Sum(nil)

	var attrs []byte // the signedAttrs SET OF, tag 0x31, when there are any
	signed := content
	if !o.NoSignedAttrs {
		attrs = o.signedAttrs(p, contentDigest)
		signed = attrs
	}
	sig, err := p.sign(o, signed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigner, err)
	}
	// ⛔ Public() matching the certificate says nothing about what Sign
	// RETURNED: a card or remote signer may sign with another key, ignore
	// the PSS options, or return nothing. Check the signature over exactly
	// the bytes signed, with the algorithm the SignerInfo claims.
	if err := o.Certificate.CheckSignature(p.x509Algo, signed, sig); err != nil {
		return nil, fmt.Errorf("%w: its signature does not verify under the certificate: %v", ErrSigner, err)
	}

	cert := o.Certificate
	serial, _ := asn1.Marshal(cert.SerialNumber) // non-nil, checked in plan
	siBody := [][]byte{
		{0x02, 0x01, 0x01}, // version 1: issuerAndSerialNumber (§5.3)
		der(0x30, cert.RawIssuer, serial),
		algID(p.digestOID, nil),
	}
	if attrs != nil {
		// §5.4: the signature covered the SET OF; the field carries the
		// same bytes under the [0] IMPLICIT tag.
		retagged := append([]byte(nil), attrs...)
		retagged[0] = 0xA0
		siBody = append(siBody, retagged)
	}
	siBody = append(siBody, algID(p.sigOID, p.sigParams), der(0x04, sig))
	signerInfo := der(0x30, siBody...)

	encap := [][]byte{oidDER(o.contentType())}
	if !o.Detached {
		encap = append(encap, der(0xA0, der(0x04, content)))
	}

	version := byte(1)
	if !o.contentType().Equal(oidData) {
		version = 3 // §5.1: eContentType other than id-data
	}
	sd := der(0x30,
		[]byte{0x02, 0x01, version},
		der(0x31, algID(p.digestOID, nil)),
		der(0x30, encap...),
		der(0xA0, o.certificateSet()...),
		der(0x31, signerInfo),
	)
	return der(0x30, oidDER(oidSignedData), der(0xA0, sd)), nil
}

// plan is the request's algorithms, decided and checked before any signing.
type plan struct {
	hash      crypto.Hash
	digestOID asn1.ObjectIdentifier
	sigOID    asn1.ObjectIdentifier
	sigParams []byte // nil: absent
	ed25519   bool
	pss       bool
	x509Algo  x509.SignatureAlgorithm // what the signature is checked with
}

func (o *SignOptions) contentType() asn1.ObjectIdentifier {
	if o.ContentType == nil {
		return oidData
	}
	return o.ContentType
}

func (o *SignOptions) plan() (*plan, error) {
	if o.Signer == nil || o.Certificate == nil {
		return nil, fmt.Errorf("%w: a signer and its certificate are both required", ErrOptions)
	}
	if len(o.Certificate.Raw) == 0 || o.Certificate.SerialNumber == nil {
		return nil, fmt.Errorf("%w: the signer's certificate is not a parsed one", ErrOptions)
	}
	for i, c := range o.Chain {
		if c == nil || len(c.Raw) == 0 {
			return nil, fmt.Errorf("%w: chain certificate %d is empty", ErrOptions, i)
		}
	}
	if err := asn1CheckOID(o.contentType()); err != nil {
		return nil, err
	}
	if o.NoSignedAttrs {
		if !o.contentType().Equal(oidData) {
			return nil, fmt.Errorf("%w: content type %v needs signed attributes (RFC 5652 §5.3)", ErrOptions, o.ContentType)
		}
		if !o.SigningTime.IsZero() || o.SigningCertificateV2 {
			return nil, fmt.Errorf("%w: signing-time and signing-certificate-v2 are signed attributes, and none were asked for", ErrOptions)
		}
	}
	if y := o.SigningTime.UTC().Year(); !o.SigningTime.IsZero() && (y < 0 || y > 9999) {
		return nil, fmt.Errorf("%w: signing time in year %d", ErrOptions, y)
	}

	pub := o.Signer.Public()
	same, ok := o.Certificate.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !same.Equal(pub) {
		return nil, fmt.Errorf("%w: the certificate's public key is not the signer's", ErrOptions)
	}

	p := &plan{hash: o.Hash}
	_, isEd := pub.(ed25519.PublicKey)
	if p.hash == 0 {
		p.hash = crypto.SHA256
		if isEd {
			p.hash = crypto.SHA512
		}
	}
	var err error
	if p.digestOID, err = oidOfHash(p.hash); err != nil {
		return nil, err
	}

	hd, _ := digestFor(p.digestOID) // found by oidOfHash just above
	if o.PSS {
		if _, isRSA := pub.(*rsa.PublicKey); !isRSA {
			return nil, fmt.Errorf("%w: RSA-PSS needs an RSA key", ErrOptions)
		}
	}
	switch pub.(type) {
	case *rsa.PublicKey:
		if o.PSS {
			p.pss = true
			p.sigOID = oidRSAPSS
			p.x509Algo = hd.pss
			p.sigParams = pssParamsDER(p.digestOID, p.hash.Size())
		} else {
			p.sigOID = oidRSAEncryption
			p.x509Algo = hd.rsa
			p.sigParams = []byte{0x05, 0x00} // NULL, as RFC 3370 §3.2 and OpenSSL write it
		}
	case *ecdsa.PublicKey:
		p.sigOID = ecdsaOID(p.hash)
		p.x509Algo = hd.ecdsa
	case ed25519.PublicKey:
		if p.hash != crypto.SHA512 {
			return nil, fmt.Errorf("%w: Ed25519 signs with SHA-512 (RFC 8419 §3.1), not %v", ErrOptions, p.hash)
		}
		// ⛔ MEASURED, NOT READ: RFC 8419 §3.2 allows Ed25519 without signed
		// attributes (§3 calls them preferred), and Verify here accepts it,
		// but OpenSSL answers "no content" (4.1.0, attached) or "invalid eddsa
		// instance" (the 3.x on CI, detached) to what this package writes.
		// Emitting a container the reference tool rejects is a defect
		// waiting for its reader, so the combination is refused.
		if o.NoSignedAttrs {
			return nil, fmt.Errorf("%w: Ed25519 is only signed with signed attributes; OpenSSL cannot verify it without them", ErrOptions)
		}
		p.ed25519 = true
		p.sigOID = oidEd25519
		p.x509Algo = x509.PureEd25519
	default:
		return nil, fmt.Errorf("%w: a %T key", ErrUnsupported, pub)
	}
	return p, nil
}

func ecdsaOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA384:
		return oidECDSAWithSHA384
	case crypto.SHA512:
		return oidECDSAWithSHA512
	}
	return oidECDSAWithSHA256
}

func oidOfHash(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	for _, row := range digests {
		if row.d.hash == h {
			return row.oid, nil
		}
	}
	if h == crypto.SHA1 {
		return nil, fmt.Errorf("%w: SHA-1 is not signed with: collisions in it are practical", ErrUnsupported)
	}
	return nil, fmt.Errorf("%w: hash function %v", ErrUnsupported, h)
}

func asn1CheckOID(oid asn1.ObjectIdentifier) error {
	if _, err := asn1.Marshal(oid); err != nil {
		return fmt.Errorf("%w: content type %v: %v", ErrOptions, oid, err)
	}
	return nil
}

// sign signs msg: its digest for RSA and ECDSA, the message itself for
// Ed25519 (RFC 8419: pure EdDSA).
func (p *plan) sign(o SignOptions, msg []byte) ([]byte, error) {
	r := o.Rand
	if r == nil {
		r = rand.Reader
	}
	if p.ed25519 {
		return o.Signer.Sign(r, msg, crypto.Hash(0))
	}
	h := p.hash.New()
	h.Write(msg)
	var opts crypto.SignerOpts = p.hash
	if p.pss {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: p.hash}
	}
	return o.Signer.Sign(r, h.Sum(nil), opts)
}

// pssParamsDER is RSASSA-PSS-params with the hash, MGF1 over it and a salt
// as long as the hash, in the form checkPSS accepts: AlgorithmIdentifiers
// without NULL parameters (RFC 5754 §2), the default trailer omitted.
func pssParamsDER(hashOID asn1.ObjectIdentifier, saltLen int) []byte {
	hashID := algID(hashOID, nil)
	mgf := algID(oidMGF1, hashID)
	salt := []byte{0x02, 0x01, byte(saltLen)} // 32, 48 or 64
	return der(0x30, der(0xA0, hashID), der(0xA1, mgf), der(0xA2, salt))
}

// signedAttrs is the SET OF Attribute, in DER: each attribute encoded, then
// the encodings sorted as octet strings (X.690 §11.6).
func (o *SignOptions) signedAttrs(p *plan, contentDigest []byte) []byte {
	attrs := [][]byte{
		attribute(oidContentType, oidDER(o.contentType())),
		attribute(oidMessageDigest, der(0x04, contentDigest)),
	}
	if !o.SigningTime.IsZero() {
		attrs = append(attrs, attribute(oidSigningTime, timeDER(o.SigningTime)))
	}
	if o.SigningCertificateV2 {
		attrs = append(attrs, attribute(oidSigningCertV2, o.signingCertificateV2(p)))
	}
	sort.Slice(attrs, func(i, j int) bool { return bytes.Compare(attrs[i], attrs[j]) < 0 })
	return der(0x31, attrs...)
}

func attribute(t asn1.ObjectIdentifier, value []byte) []byte {
	return der(0x30, oidDER(t), der(0x31, value))
}

// timeDER is Time (§11.3): UTCTime for 1950 through 2049, GeneralizedTime
// outside, UTC and whole seconds either way.
func timeDER(t time.Time) []byte {
	t = t.UTC()
	if y := t.Year(); y >= 1950 && y <= 2049 {
		return der(0x17, []byte(t.Format("060102150405Z")))
	}
	return der(0x18, []byte(t.Format("20060102150405Z")))
}

// signingCertificateV2 is SigningCertificateV2 with one ESSCertIDv2 (RFC 5035
// §5.4.1): the hash of the signer's certificate, under the signature's own
// digest, and its IssuerSerial. hashAlgorithm is DEFAULT id-sha256, so DER
// leaves it out for SHA-256.
func (o *SignOptions) signingCertificateV2(p *plan) []byte {
	h := p.hash.New()
	h.Write(o.Certificate.Raw)
	var id [][]byte
	if p.hash != crypto.SHA256 {
		id = append(id, algID(p.digestOID, nil))
	}
	serial, _ := asn1.Marshal(o.Certificate.SerialNumber)
	generalNames := der(0x30, der(0xA4, o.Certificate.RawIssuer)) // directoryName
	id = append(id, der(0x04, h.Sum(nil)), der(0x30, generalNames, serial))
	return der(0x30, der(0x30, der(0x30, id...)))
}

// certificateSet is the signer's certificate and the chain, deduplicated and
// sorted so the SET OF is DER.
func (o *SignOptions) certificateSet() [][]byte {
	all := [][]byte{o.Certificate.Raw}
	for _, c := range o.Chain {
		all = append(all, c.Raw)
	}
	sort.Slice(all, func(i, j int) bool { return bytes.Compare(all[i], all[j]) < 0 })
	out := all[:0]
	for i, c := range all {
		if i == 0 || !bytes.Equal(c, all[i-1]) {
			out = append(out, c)
		}
	}
	return out
}

// --- DER, by hand: every tag used here is below 31 and every body is known,
// so an encoder with no error path is shorter than encoding/asn1 struct tags
// and cannot fail.

func der(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := []byte{tag}
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	default:
		l := new(big.Int).SetInt64(int64(n)).Bytes()
		out = append(out, 0x80|byte(len(l)))
		out = append(out, l...)
	}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func oidDER(oid asn1.ObjectIdentifier) []byte {
	b, _ := asn1.Marshal(oid) // every caller has passed asn1CheckOID or is a constant
	return b
}

// algID is AlgorithmIdentifier; params is the complete DER of the parameters,
// or nil for absent.
func algID(oid asn1.ObjectIdentifier, params []byte) []byte {
	return der(0x30, oidDER(oid), params)
}
