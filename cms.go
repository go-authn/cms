// Package cms reads, verifies and signs CMS SignedData (RFC 5652): the
// container a PDF signature, a UEFI authenticated variable and an S/MIME
// message carry. Sign produces one; see SignOptions.
//
// Parse reads the structure; (*SignedData).Verify checks every signer's
// signature against the signed content and returns the certificate each one
// used. Whether that certificate should be TRUSTED — its chain, its validity
// period, its revocation — is a separate question that RFC 5652 §5.6 places
// "beyond the scope of this document", and so does this package: hand the
// returned certificates to crypto/x509's Verify, and to go-authn/revocation
// for CRLs.
//
// ⛔ DER ONLY, for now. RFC 5652 lets the outer structure be BER, and some
// producers write indefinite lengths; encoding/asn1 does not read them, and a
// structure that cannot be read is REFUSED with ErrMalformed rather than
// guessed at. The signed attributes themselves must be DER in every case
// (§5.3), so this limit never weakens what is verified — it only refuses
// some well-formed inputs that a BER-to-DER pass would accept.
package cms

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// The errors every failure wraps, so a caller can tell "this is not a
// signature" from "this is a signature I cannot check" from "this signature
// is wrong" — three answers RFC 5652 §5.1 asks an implementation to keep
// apart ("MUST gracefully handle unimplemented signature algorithms").
var (
	// ErrMalformed: the bytes are not a SignedData this package can read.
	ErrMalformed = errors.New("cms: malformed")
	// ErrUnsupported: well-formed, but uses something this package does not
	// implement (an algorithm, SHA-1, a certificate it cannot find).
	ErrUnsupported = errors.New("cms: unsupported")
	// ErrInvalid: readable and supported, and the signature does not hold.
	ErrInvalid = errors.New("cms: signature invalid")
)

// maxInput bounds what Parse will read. A PDF signature's /Contents is
// typically a few kilobytes and rarely past 64 KiB; sixteen mebibytes leaves
// room for a container carrying a long chain and its CRLs while refusing an
// input that is a denial of service rather than a signature. A var, so tests
// can lower it.
var maxInput = 16 << 20

// maxSigners bounds how many SignerInfos one SignedData may carry.
//
// ⛔ A SIZE BOUND IS NOT A WORK BOUND, and review measured the difference.
// Every signer is checked over the WHOLE content, and nothing stops a file
// from repeating one valid, self-signed signer: 4 000 copies in a 5 MB input
// over 4 MiB of content took 25 s of CPU, and the 16 MiB limit would allow
// about forty thousand — minutes, from one file. A PDF signature has one
// signer and S/MIME rarely more than a few; sixteen is generous. Verify also
// hashes the content once per digest algorithm rather than once per signer,
// but that alone does not close it: an Ed25519 signer without signed
// attributes hashes the content inside ed25519.Verify, every time.
var maxSigners = 16

// The object identifiers this package recognises (RFC 5652 §5.1, §11.1,
// §11.2; RFC 5754 for the SHA-2 digests).
var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

// SignedData is a parsed CMS SignedData.
type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier
	// ContentType is encapContentInfo's eContentType: id-data for a PDF
	// signature and for most others.
	ContentType asn1.ObjectIdentifier
	// Content is the encapsulated content, or nil when the signature is
	// DETACHED — as a PDF signature always is: the signed bytes are the
	// file's /ByteRange, and Verify takes them as its argument.
	Content []byte
	// Certificates are those the SignedData carries. Certificate choices
	// other than an X.509 certificate (attribute certificates, "other") are
	// skipped and counted in SkippedCertificates.
	Certificates        []*x509.Certificate
	SkippedCertificates int
	Signers             []Signer
}

// Signer is one SignerInfo.
type Signer struct {
	Version int
	// Exactly one of IssuerAndSerial and SubjectKeyID is set: RFC 5652 §5.3
	// requires a recipient to accept both forms of SignerIdentifier.
	IssuerAndSerial *IssuerAndSerial
	SubjectKeyID    []byte

	DigestAlgorithm pkix.AlgorithmIdentifier
	// SignedAttrs is nil when the signer signed the content directly.
	SignedAttrs        []Attribute
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte

	// signedAttrsDER is the signedAttrs field exactly as it arrived, [0]
	// IMPLICIT tag included: §5.4 has the signature cover this encoding with
	// that tag rewritten to SET OF, so the bytes are kept rather than
	// re-encoded — a re-encoding that differed in any way would verify
	// something other than what was signed.
	signedAttrsDER []byte
}

// IssuerAndSerial identifies a certificate by its issuer's name, as encoded,
// and its serial number.
type IssuerAndSerial struct {
	RawIssuer []byte
	Serial    *big.Int
}

// Attribute is one signed attribute: a type and its values, each value kept
// as its complete DER encoding.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values [][]byte
}

// The ASN.1 shapes, as encoding/asn1 reads them.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedDataASN1 struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue    `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue    `asn1:"optional,tag:1"`
	SignerInfos      []signerInfoASN1 `asn1:"set"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type signerInfoASN1 struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerialASN1 struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attributeASN1 struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// Parse reads a DER-encoded ContentInfo holding a SignedData.
func Parse(der []byte) (*SignedData, error) {
	if len(der) > maxInput {
		return nil, fmt.Errorf("%w: %d bytes is past the limit of %d", ErrMalformed, len(der), maxInput)
	}
	var ci contentInfo
	if err := unmarshalAll(der, &ci, "ContentInfo"); err != nil {
		return nil, err
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("%w: content type %v is not signed-data", ErrUnsupported, ci.ContentType)
	}
	var raw signedDataASN1
	if err := unmarshalAll(ci.Content.Bytes, &raw, "SignedData"); err != nil {
		return nil, err
	}

	sd := &SignedData{
		Version:          raw.Version,
		DigestAlgorithms: raw.DigestAlgorithms,
		ContentType:      raw.EncapContentInfo.EContentType,
	}
	if len(raw.EncapContentInfo.EContent.FullBytes) > 0 {
		// ⛔ .Bytes, NOT .FullBytes. encoding/asn1 keeps the OUTER element
		// in a RawValue's FullBytes even for an `explicit` field, so
		// FullBytes here is the [0] wrapper and .Bytes is the OCTET STRING
		// inside it. The first version decoded the wrapper as an OCTET
		// STRING, and so could read NO attached signature at all —
		// detached ones never reach this line, which is why they passed.
		// OpenSSL's verdict on its own -nodetach output is what caught it.
		var content []byte
		if err := unmarshalAll(raw.EncapContentInfo.EContent.Bytes, &content, "eContent"); err != nil {
			return nil, err
		}
		// ⛔ A present-but-empty eContent must stay an empty, NON-nil slice:
		// nil means "detached", and an attached empty content is a different
		// statement Verify must not mistake for it. encoding/asn1 already
		// returns a non-nil slice for a zero-length OCTET STRING, so there is
		// no branch here — an earlier one was unreachable, and coverage said
		// so. TestWhatParseKeepsRatherThanRefuses is the guard: it fails the
		// day that behaviour changes, which a dead branch never would.
		sd.Content = content
	}

	if len(raw.Certificates.FullBytes) > 0 {
		if err := sd.readCertificates(raw.Certificates.Bytes); err != nil {
			return nil, err
		}
	}

	if len(raw.SignerInfos) > maxSigners {
		return nil, fmt.Errorf("%w: %d signers, past the limit of %d — each is checked over the whole content",
			ErrUnsupported, len(raw.SignerInfos), maxSigners)
	}
	for i, rs := range raw.SignerInfos {
		s, err := readSigner(rs)
		if err != nil {
			return nil, fmt.Errorf("signer %d: %w", i, err)
		}
		sd.Signers = append(sd.Signers, s)
	}
	return sd, nil
}

// unmarshalAll reads exactly one value from b into v, and refuses trailing
// bytes: a structure followed by more data is not the structure it claims.
func unmarshalAll(b []byte, v any, what string) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrMalformed, what, err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("%w: %s is followed by %d trailing byte(s)", ErrMalformed, what, len(rest))
	}
	return nil
}

// readCertificates reads the CertificateSet: X.509 certificates are parsed,
// and the other CertificateChoices — context-tagged attribute certificates
// and "other" — are skipped and counted rather than refused, since a signer
// may legitimately carry them and they say nothing about the signature.
func (sd *SignedData) readCertificates(b []byte) error {
	for len(b) > 0 {
		var rv asn1.RawValue
		rest, err := asn1.Unmarshal(b, &rv)
		if err != nil {
			return fmt.Errorf("%w: certificates: %v", ErrMalformed, err)
		}
		b = rest
		if rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagSequence {
			c, err := x509.ParseCertificate(rv.FullBytes)
			if err != nil {
				return fmt.Errorf("%w: certificate %d: %v", ErrMalformed, len(sd.Certificates), err)
			}
			sd.Certificates = append(sd.Certificates, c)
			continue
		}
		sd.SkippedCertificates++
	}
	return nil
}

func readSigner(rs signerInfoASN1) (Signer, error) {
	s := Signer{
		Version:            rs.Version,
		DigestAlgorithm:    rs.DigestAlgorithm,
		SignatureAlgorithm: rs.SignatureAlgorithm,
		Signature:          rs.Signature,
	}
	switch {
	case rs.SID.Class == asn1.ClassUniversal && rs.SID.Tag == asn1.TagSequence:
		var ias issuerAndSerialASN1
		if err := unmarshalAll(rs.SID.FullBytes, &ias, "issuerAndSerialNumber"); err != nil {
			return s, err
		}
		s.IssuerAndSerial = &IssuerAndSerial{RawIssuer: ias.Issuer.FullBytes, Serial: ias.Serial}
	case rs.SID.Class == asn1.ClassContextSpecific && rs.SID.Tag == 0 && !rs.SID.IsCompound:
		// [0] IMPLICIT SubjectKeyIdentifier, an OCTET STRING whose tag the
		// IMPLICIT replaced, so its bytes are the key identifier itself.
		s.SubjectKeyID = rs.SID.Bytes
	default:
		return s, fmt.Errorf("%w: a signer identifier of class %d tag %d", ErrMalformed, rs.SID.Class, rs.SID.Tag)
	}

	if len(rs.SignedAttrs.FullBytes) > 0 {
		// ⛔⛔ [0] IMPLICIT SET OF is CONSTRUCTED: the tag byte is 0xA0, never
		// 0x80. encoding/asn1 matches an `optional,tag:0` RawValue on class
		// and number alone, so the first version accepted a primitive 0x80
		// as well — and since §5.4 has the signed bytes rewritten to 0x31
		// either way, a one-bit change to a valid signature still VERIFIED.
		// That is malleability, not a forgery of content, but it is two
		// encodings of one signature, and it is exactly what this package's
		// own fuzz invariant calls a forgery: the fuzzer never found the
		// one-bit flip, external review did. OpenSSL 4.1.0 accepts it too.
		if !rs.SignedAttrs.IsCompound {
			return s, fmt.Errorf("%w: signedAttrs is not a constructed [0] (tag byte %#x)", ErrMalformed, rs.SignedAttrs.FullBytes[0])
		}
		attrs, err := readAttributes(rs.SignedAttrs.Bytes)
		if err != nil {
			return s, err
		}
		// ⛔ SIZE (1..MAX): a present but empty SET is not "no attributes",
		// it is malformed — and accepting it would let a signer sign an
		// empty attribute set that binds no content at all.
		if len(attrs) == 0 {
			return s, fmt.Errorf("%w: signedAttrs is present and empty", ErrMalformed)
		}
		s.SignedAttrs = attrs
		s.signedAttrsDER = rs.SignedAttrs.FullBytes
	}
	return s, nil
}

// readAttributes reads a SET OF Attribute, field by field.
//
// ⛔ BY HAND, because two shapes encoding/asn1 lets through are not DER and
// §5.3 requires DER here. Unmarshalling into a struct accepts an Attribute
// SEQUENCE with TRAILING elements after its values, and an `asn1:"set"`
// RawValue matches ANY tag, so attrValues need not be a SET at all. Neither
// lets anyone but the signer change what was signed — the bytes are hashed as
// they arrived — but each is a second encoding of one attribute, and the
// first is how a parser and a reader come to disagree about a structure.
func readAttributes(b []byte) ([]Attribute, error) {
	var out []Attribute
	for len(b) > 0 {
		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(b, &seq)
		if err != nil {
			return nil, fmt.Errorf("%w: signed attribute: %v", ErrMalformed, err)
		}
		b = rest
		if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
			return nil, fmt.Errorf("%w: a signed attribute that is not a SEQUENCE", ErrMalformed)
		}
		var a attributeASN1
		inner, err := asn1.Unmarshal(seq.Bytes, &a.Type)
		if err != nil {
			return nil, fmt.Errorf("%w: signed attribute type: %v", ErrMalformed, err)
		}
		inner, err = asn1.Unmarshal(inner, &a.Values)
		if err != nil {
			// ⛔ Worded so no other refusal CONTAINS it. This once read
			// "values of attribute", which the "are not a SET" refusal below
			// also contains — so with this guard deleted, its test still
			// passed on the other message, and a mutation sweep marked it a
			// survivor. A message assertion is only as specific as the words
			// it can match.
			return nil, fmt.Errorf("%w: attribute %v carries no readable value set: %v", ErrMalformed, a.Type, err)
		}
		if a.Values.Class != asn1.ClassUniversal || a.Values.Tag != asn1.TagSet || !a.Values.IsCompound {
			return nil, fmt.Errorf("%w: the values of attribute %v are not a SET", ErrMalformed, a.Type)
		}
		if len(inner) != 0 {
			return nil, fmt.Errorf("%w: attribute %v is followed by %d byte(s) inside its SEQUENCE", ErrMalformed, a.Type, len(inner))
		}
		attr := Attribute{Type: a.Type}
		vb := a.Values.Bytes
		for len(vb) > 0 {
			var v asn1.RawValue
			vrest, err := asn1.Unmarshal(vb, &v)
			if err != nil {
				return nil, fmt.Errorf("%w: value of attribute %v: %v", ErrMalformed, a.Type, err)
			}
			vb = vrest
			attr.Values = append(attr.Values, v.FullBytes)
		}
		out = append(out, attr)
	}
	return out, nil
}
