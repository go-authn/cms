package cms

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	_ "crypto/sha256" // register SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // register SHA-384 and SHA-512
)

// The digest and signature algorithm identifiers this package implements.
// SHA-1 is recognised in order to be refused BY NAME rather than as an
// unknown OID: a signer that used it should hear why it was turned down.
var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAPSS        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidMGF1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// Verify checks every signer's signature and returns the certificate each
// signer used, in signer order.
//
// detached is the signed content when the SignedData does not carry it — for
// a PDF signature, the concatenation of the file's /ByteRange. It must be nil
// when the content is attached: supplying content that the container also
// carries is refused rather than silently preferring one of the two.
//
// ⛔ EVERY signer must verify. RFC 5652 §5.1 lets an application treat one
// good signature from a given signer as enough when that signer signed
// several times; a caller that wants that can verify signers itself. A
// container with no signers at all is refused: it signs nothing.
//
// The returned certificates are only those that SIGNED. Whether to trust them
// — chain, validity, revocation — is the caller's, per §5.6.
func (sd *SignedData) Verify(detached []byte) ([]*x509.Certificate, error) {
	content := sd.Content
	switch {
	case content != nil && detached != nil:
		return nil, fmt.Errorf("%w: the content is attached and was also supplied", ErrMalformed)
	case content == nil && detached == nil:
		return nil, fmt.Errorf("%w: a detached signature needs the content it signed", ErrMalformed)
	case content == nil:
		content = detached
	}
	if len(sd.Signers) == 0 {
		return nil, fmt.Errorf("%w: no signers: a SignedData with none signs nothing", ErrInvalid)
	}
	certs := make([]*x509.Certificate, 0, len(sd.Signers))
	for i := range sd.Signers {
		c, err := sd.verifySigner(&sd.Signers[i], content)
		if err != nil {
			return nil, fmt.Errorf("signer %d: %w", i, err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func (sd *SignedData) verifySigner(s *Signer, content []byte) (*x509.Certificate, error) {
	cert := sd.signerCertificate(s)
	if cert == nil {
		return nil, fmt.Errorf("%w: the signer's certificate is not in the SignedData", ErrUnsupported)
	}
	d, err := digestFor(s.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	algo, err := signatureAlgorithm(s.SignatureAlgorithm, d)
	if err != nil {
		return nil, err
	}

	signed := content
	if s.SignedAttrs != nil {
		if err := sd.checkSignedAttrs(s, d.hash, content); err != nil {
			return nil, err
		}
		// §5.4: the signature covers the DER of signedAttrs with its [0]
		// IMPLICIT tag replaced by the SET OF tag. Only the tag byte
		// changes — length and contents are the bytes that arrived — so a
		// copy is retagged rather than the attributes re-encoded.
		signed = append([]byte(nil), s.signedAttrsDER...)
		signed[0] = 0x31
	} else if !sd.ContentType.Equal(oidData) {
		// §5.3: signedAttrs "MUST be present if the content type ... is
		// not id-data". Without them the content type is not signed at
		// all, and a verifier that accepted this would let a signature
		// over one kind of content be presented as another.
		return nil, fmt.Errorf("%w: content type %v without signed attributes", ErrMalformed, sd.ContentType)
	}

	if err := cert.CheckSignature(algo, signed, s.Signature); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return cert, nil
}

// checkSignedAttrs enforces §5.3, §5.6, §11.1 and §11.2: exactly one
// content-type and exactly one message-digest, each with exactly one value;
// the content type equal to eContentType; and the digest equal to the one
// THIS side computes — "The recipient MUST NOT rely on any message digest
// values computed by the originator."
func (sd *SignedData) checkSignedAttrs(s *Signer, h crypto.Hash, content []byte) error {
	ctDER, err := singleValue(s.SignedAttrs, oidContentType, "content-type")
	if err != nil {
		return err
	}
	var ct asn1.ObjectIdentifier
	if err := unmarshalAll(ctDER, &ct, "content-type attribute"); err != nil {
		return err
	}
	if !ct.Equal(sd.ContentType) {
		return fmt.Errorf("%w: the signed content type is %v and the content is %v", ErrInvalid, ct, sd.ContentType)
	}

	mdDER, err := singleValue(s.SignedAttrs, oidMessageDigest, "message-digest")
	if err != nil {
		return err
	}
	var md []byte
	if err := unmarshalAll(mdDER, &md, "message-digest attribute"); err != nil {
		return err
	}
	hh := h.New()
	hh.Write(content)
	if subtle.ConstantTimeCompare(hh.Sum(nil), md) != 1 {
		return fmt.Errorf("%w: the content's digest is not the one the signer signed", ErrInvalid)
	}
	return nil
}

// singleValue returns the one value of the one attribute of type t, and
// refuses zero or several of either. §11.1 and §11.2 forbid both, and the
// reason is not pedantry: with two message-digest attributes, a verifier that
// checked the first while a reader trusted the second would be fooled.
func singleValue(attrs []Attribute, t asn1.ObjectIdentifier, name string) ([]byte, error) {
	var found *Attribute
	for i := range attrs {
		if !attrs[i].Type.Equal(t) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: more than one %s attribute", ErrMalformed, name)
		}
		found = &attrs[i]
	}
	if found == nil {
		return nil, fmt.Errorf("%w: no %s attribute among the signed attributes", ErrMalformed, name)
	}
	if len(found.Values) != 1 {
		return nil, fmt.Errorf("%w: the %s attribute has %d values, not one", ErrMalformed, name, len(found.Values))
	}
	return found.Values[0], nil
}

// signerCertificate finds the certificate a SignerIdentifier names, by issuer
// and serial or by subject key identifier (§5.3 requires a recipient to
// accept both).
func (sd *SignedData) signerCertificate(s *Signer) *x509.Certificate {
	for _, c := range sd.Certificates {
		switch {
		case s.IssuerAndSerial != nil:
			if bytes.Equal(c.RawIssuer, s.IssuerAndSerial.RawIssuer) &&
				c.SerialNumber.Cmp(s.IssuerAndSerial.Serial) == 0 {
				return c
			}
		case len(s.SubjectKeyID) > 0:
			if bytes.Equal(c.SubjectKeyId, s.SubjectKeyID) {
				return c
			}
		}
	}
	return nil
}

// digest is one accepted digest algorithm together with the crypto/x509
// signature algorithm each key family uses with it.
//
// ⭐ THE PAIRING IS DATA, SO AN UNSUPPORTED ONE CANNOT BE EXPRESSED. A first
// version mapped (signature OID, hash) through a switch with an error branch
// for "a hash this signature algorithm does not support" — a branch no input
// could reach, since the digest lookup only ever returns these three. An
// error path nothing can reach is either dead code or a function safe only
// when called correctly, and neither belongs in a verifier. A row carries
// its own pairings instead.
type digest struct {
	hash            crypto.Hash
	rsa, pss, ecdsa x509.SignatureAlgorithm
}

var digests = []struct {
	oid asn1.ObjectIdentifier
	d   digest
}{
	{oidSHA256, digest{crypto.SHA256, x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256}},
	{oidSHA384, digest{crypto.SHA384, x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384}},
	{oidSHA512, digest{crypto.SHA512, x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512}},
}

func digestFor(oid asn1.ObjectIdentifier) (digest, error) {
	for _, row := range digests {
		if row.oid.Equal(oid) {
			return row.d, nil
		}
	}
	if oid.Equal(oidSHA1) {
		return digest{}, fmt.Errorf("%w: SHA-1 digests are not accepted: collisions in it are practical", ErrUnsupported)
	}
	return digest{}, fmt.Errorf("%w: digest algorithm %v", ErrUnsupported, oid)
}

// signatureAlgorithm maps a SignerInfo's signatureAlgorithm, together with its
// digestAlgorithm, onto the crypto/x509 algorithm that checks it.
//
// ⛔ When the signature OID names a hash of its own — sha256WithRSAEncryption,
// ecdsa-with-SHA384 — that hash must be the digestAlgorithm's. The
// message-digest attribute is computed with digestAlgorithm and the signature
// with the OID's hash; letting them differ would mean one SignerInfo making
// two statements about which hash protects it, and only one being checked.
func signatureAlgorithm(ai pkix.AlgorithmIdentifier, d digest) (x509.SignatureAlgorithm, error) {
	oid := ai.Algorithm
	same := func(want crypto.Hash, algo x509.SignatureAlgorithm) (x509.SignatureAlgorithm, error) {
		if d.hash != want {
			return 0, fmt.Errorf("%w: signature algorithm %v uses %v but the digest algorithm is %v", ErrMalformed, oid, want, d.hash)
		}
		return algo, nil
	}
	switch {
	case oid.Equal(oidRSAEncryption):
		return d.rsa, nil
	case oid.Equal(oidSHA256WithRSA):
		return same(crypto.SHA256, x509.SHA256WithRSA)
	case oid.Equal(oidSHA384WithRSA):
		return same(crypto.SHA384, x509.SHA384WithRSA)
	case oid.Equal(oidSHA512WithRSA):
		return same(crypto.SHA512, x509.SHA512WithRSA)
	case oid.Equal(oidRSAPSS):
		if err := checkPSS(ai.Parameters.FullBytes, d.hash); err != nil {
			return 0, err
		}
		return d.pss, nil
	case oid.Equal(oidECPublicKey):
		return d.ecdsa, nil
	case oid.Equal(oidECDSAWithSHA256):
		return same(crypto.SHA256, x509.ECDSAWithSHA256)
	case oid.Equal(oidECDSAWithSHA384):
		return same(crypto.SHA384, x509.ECDSAWithSHA384)
	case oid.Equal(oidECDSAWithSHA512):
		return same(crypto.SHA512, x509.ECDSAWithSHA512)
	case oid.Equal(oidEd25519):
		// RFC 8419: pure EdDSA signs the message itself, with no hash of
		// its own, so there is no second hash to disagree with.
		return x509.PureEd25519, nil
	}
	return 0, fmt.Errorf("%w: signature algorithm %v", ErrUnsupported, oid)
}

type pssParams struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0,optional"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1,optional"`
	SaltLength   int                      `asn1:"explicit,tag:2,optional,default:20"`
	TrailerField int                      `asn1:"explicit,tag:3,optional,default:1"`
}

// checkPSS accepts exactly the RSASSA-PSS parameters crypto/x509 verifies:
// the digest's hash, MGF1 with that same hash, a salt as long as the hash,
// and the standard trailer. Anything else is refused BY NAME, because
// CheckSignature would otherwise reject it with an error that does not say
// which parameter was the problem — or, worse, a caller would think a PSS
// signature with other parameters had been checked when it had not.
func checkPSS(params []byte, h crypto.Hash) error {
	if len(params) == 0 {
		return fmt.Errorf("%w: RSASSA-PSS without parameters", ErrMalformed)
	}
	var p pssParams
	if err := unmarshalAll(params, &p, "RSASSA-PSS parameters"); err != nil {
		return err
	}
	pd, err := digestFor(p.Hash.Algorithm)
	if err != nil {
		return fmt.Errorf("RSASSA-PSS hash: %w", err)
	}
	if pd.hash != h {
		return fmt.Errorf("%w: RSASSA-PSS uses %v but the digest algorithm is %v", ErrMalformed, pd.hash, h)
	}
	if !p.MGF.Algorithm.Equal(oidMGF1) {
		return fmt.Errorf("%w: RSASSA-PSS mask generation %v", ErrUnsupported, p.MGF.Algorithm)
	}
	var mgfHash pkix.AlgorithmIdentifier
	if err := unmarshalAll(p.MGF.Parameters.FullBytes, &mgfHash, "MGF1 hash"); err != nil {
		return err
	}
	md, err := digestFor(mgfHash.Algorithm)
	if err != nil {
		return fmt.Errorf("MGF1 hash: %w", err)
	}
	if md.hash != h {
		return fmt.Errorf("%w: MGF1 uses %v and the signature %v", ErrUnsupported, md.hash, h)
	}
	if p.SaltLength != h.Size() {
		return fmt.Errorf("%w: RSASSA-PSS salt of %d bytes; only the hash length, %d, is checked", ErrUnsupported, p.SaltLength, h.Size())
	}
	if p.TrailerField != 1 {
		return fmt.Errorf("%w: RSASSA-PSS trailer field %d", ErrMalformed, p.TrailerField)
	}
	return nil
}
