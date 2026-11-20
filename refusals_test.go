package cms

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
)

var bigOne = big.NewInt(1)

// must is asn1.Marshal for tests: a value that cannot be encoded is a bug in
// the test, not a case being tested.
func must(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ctx0(t *testing.T, inner []byte) []byte {
	t.Helper()
	return must(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
}

// signedDataInfo wraps arbitrary bytes as the [0] content of a signed-data
// ContentInfo, so Parse reaches the SignedData decoder with them.
func signedDataInfo(t *testing.T, inner []byte) []byte {
	t.Helper()
	return must(t, struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
}

func wantRefusal(t *testing.T, err error, class error, says string) {
	t.Helper()
	if !errorsIs(err, class) || !strings.Contains(err.Error(), says) {
		t.Fatalf("got %v\nwant %v containing %q", err, class, says)
	}
}

// TestParseRefusesWhatAHostileSignerControls covers the decoders below the
// envelope. Every one of these fields is a RawValue whose BYTES a signer
// writes freely — encoding/asn1 checked only the outer tag and length — so
// each inner decode is a real refusal, not a defensive one.
func TestParseRefusesWhatAHostileSignerControls(t *testing.T) {
	sha256 := pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	ias := must(t, issuerAndSerialASN1{Issuer: asn1.RawValue{FullBytes: must(t, pkix.RDNSequence{})}, Serial: bigOne})
	signerWith := func(sid asn1.RawValue, attrs asn1.RawValue) []byte {
		return must(t, signedDataASN1{
			Version:          1,
			DigestAlgorithms: []pkix.AlgorithmIdentifier{sha256},
			EncapContentInfo: encapContentInfo{EContentType: oidData},
			SignerInfos: []signerInfoASN1{{
				Version: 1, SID: sid, DigestAlgorithm: sha256, SignedAttrs: attrs,
				SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption}, Signature: []byte{1},
			}},
		})
	}
	withCerts := func(certs []byte) []byte {
		return must(t, signedDataASN1{
			Version:          1,
			DigestAlgorithms: []pkix.AlgorithmIdentifier{sha256},
			EncapContentInfo: encapContentInfo{EContentType: oidData},
			Certificates:     asn1.RawValue{FullBytes: ctx0(t, certs)},
		})
	}
	withContent := func(eContent []byte) []byte {
		return must(t, signedDataASN1{
			Version:          1,
			DigestAlgorithms: []pkix.AlgorithmIdentifier{sha256},
			EncapContentInfo: encapContentInfo{EContentType: oidData, EContent: asn1.RawValue{FullBytes: ctx0(t, eContent)}},
		})
	}
	attrsOf := func(b []byte) asn1.RawValue { return asn1.RawValue{FullBytes: ctx0(t, b)} }

	for _, tc := range []struct {
		name  string
		inner []byte
		says  string
	}{
		{"a SignedData that is not one", []byte{0x02, 0x01, 0x00}, "SignedData"},
		{"an eContent that is not an OCTET STRING", withContent(must(t, 7)), "eContent"},
		{"certificates whose bytes are not DER", withCerts([]byte{0x30}), "certificates"},
		{"a SEQUENCE among the certificates that is not a certificate", withCerts(must(t, []int{1})), "certificate 0"},
		{"an issuerAndSerialNumber that is not one", signerWith(asn1.RawValue{FullBytes: must(t, []int{1})}, asn1.RawValue{}), "issuerAndSerialNumber"},
		{"a signer identifier of neither form", signerWith(asn1.RawValue{FullBytes: must(t, 5)}, asn1.RawValue{}), "signer identifier of class 0 tag 2"},
		{"signed attributes that are not DER", signerWith(asn1.RawValue{FullBytes: ias}, attrsOf([]byte{0x30})), "signed attribute"},
		{"an attribute value that is not DER", signerWith(asn1.RawValue{FullBytes: ias},
			attrsOf(must(t, struct {
				Type   asn1.ObjectIdentifier
				Values asn1.RawValue
			}{oidMessageDigest, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: []byte{0x04}}}))),
			"value of attribute"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(signedDataInfo(t, tc.inner))
			wantRefusal(t, err, ErrMalformed, tc.says)
		})
	}
}

// TestWhatParseKeepsRatherThanRefuses pins the two inputs that are odd and
// still well-formed: an attached EMPTY content, which must stay distinguishable
// from a detached one, and a certificate choice that is not an X.509
// certificate, which is counted and skipped.
func TestWhatParseKeepsRatherThanRefuses(t *testing.T) {
	sha256 := pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	empty := must(t, signedDataASN1{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{sha256},
		EncapContentInfo: encapContentInfo{EContentType: oidData, EContent: asn1.RawValue{FullBytes: ctx0(t, must(t, []byte{}))}},
	})
	sd, err := Parse(signedDataInfo(t, empty))
	if err != nil {
		t.Fatal(err)
	}
	if sd.Content == nil || len(sd.Content) != 0 {
		t.Fatalf("an attached empty content read as %#v; nil would mean detached", sd.Content)
	}

	// [1] IMPLICIT, an obsolete attribute-certificate choice: skipped.
	other := must(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: must(t, 1)})
	skipped := must(t, signedDataASN1{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{sha256},
		EncapContentInfo: encapContentInfo{EContentType: oidData},
		Certificates:     asn1.RawValue{FullBytes: ctx0(t, other)},
	})
	sd, err = Parse(signedDataInfo(t, skipped))
	if err != nil {
		t.Fatal(err)
	}
	if sd.SkippedCertificates != 1 || len(sd.Certificates) != 0 {
		t.Fatalf("skipped %d, kept %d", sd.SkippedCertificates, len(sd.Certificates))
	}
}

// TestAttributeValuesOfTheWrongType covers §11.1 and §11.2's value types: a
// content-type that is not an OBJECT IDENTIFIER and a message-digest that is
// not an OCTET STRING are refused as such, before the digest is compared.
func TestAttributeValuesOfTheWrongType(t *testing.T) {
	content := read(t, "content")
	for _, tc := range []struct {
		name string
		attr asn1.ObjectIdentifier
		says string
	}{
		{"a content-type that is not an OID", oidContentType, "content-type attribute"},
		{"a message-digest that is not an OCTET STRING", oidMessageDigest, "message-digest attribute"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der := rebuild(t, "rsa-detached.der", func(sd *signedDataASN1) {
				a := without(attrsOf(t, sd), tc.attr)
				setAttrs(t, sd, append(a, Attribute{tc.attr, [][]byte{must(t, true)}}))
			})
			sd, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			_, err = sd.Verify(content)
			wantRefusal(t, err, ErrMalformed, tc.says)
		})
	}
}

// TestSignatureAlgorithmPairings walks every signature OID this package
// accepts, with its digest's pairing and — for the OIDs that name a hash of
// their own — with a digest that disagrees.
func TestSignatureAlgorithmPairings(t *testing.T) {
	d := func(oid asn1.ObjectIdentifier) digest {
		r, err := digestFor(oid)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	sha256, sha384, sha512 := d(oidSHA256), d(oidSHA384), d(oidSHA512)
	ai := func(oid asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
		return pkix.AlgorithmIdentifier{Algorithm: oid}
	}
	for _, tc := range []struct {
		oid  asn1.ObjectIdentifier
		with digest
		want x509.SignatureAlgorithm
	}{
		{oidRSAEncryption, sha384, x509.SHA384WithRSA},
		{oidSHA256WithRSA, sha256, x509.SHA256WithRSA},
		{oidSHA384WithRSA, sha384, x509.SHA384WithRSA},
		{oidSHA512WithRSA, sha512, x509.SHA512WithRSA},
		{oidECPublicKey, sha512, x509.ECDSAWithSHA512},
		{oidECDSAWithSHA256, sha256, x509.ECDSAWithSHA256},
		{oidECDSAWithSHA384, sha384, x509.ECDSAWithSHA384},
		{oidECDSAWithSHA512, sha512, x509.ECDSAWithSHA512},
		{oidEd25519, sha512, x509.PureEd25519},
	} {
		got, err := signatureAlgorithm(ai(tc.oid), tc.with)
		if err != nil || got != tc.want {
			t.Errorf("%v with %v: %v, %v; want %v", tc.oid, tc.with.hash, got, err, tc.want)
		}
	}
	for _, oid := range []asn1.ObjectIdentifier{oidSHA512WithRSA, oidECDSAWithSHA256, oidECDSAWithSHA384, oidECDSAWithSHA512} {
		_, err := signatureAlgorithm(ai(oid), sha384)
		if oid.Equal(oidECDSAWithSHA384) {
			if err != nil {
				t.Errorf("%v with SHA-384: %v", oid, err)
			}
			continue
		}
		wantRefusal(t, err, ErrMalformed, "but the digest algorithm is SHA-384")
	}
}

// pss builds RSASSA-PSS parameters.
func pss(t *testing.T, hash, mgf, mgfHash asn1.ObjectIdentifier, salt, trailer int) []byte {
	t.Helper()
	return must(t, pssParams{
		Hash: pkix.AlgorithmIdentifier{Algorithm: hash},
		MGF: pkix.AlgorithmIdentifier{Algorithm: mgf,
			Parameters: asn1.RawValue{FullBytes: must(t, pkix.AlgorithmIdentifier{Algorithm: mgfHash})}},
		SaltLength:   salt,
		TrailerField: trailer,
	})
}

// TestPSSParametersOutsideWhatIsChecked: crypto/x509 verifies PSS with the
// digest's hash, MGF1 over that hash, and a hash-length salt. Every other
// combination is refused NAMING the parameter, rather than reaching
// CheckSignature and failing with an error that does not say which.
func TestPSSParametersOutsideWhatIsChecked(t *testing.T) {
	h := crypto.SHA256
	// ⛔ WELL-FORMED DER THAT IS NOT AN AlgorithmIdentifier — an INTEGER. The
	// first version used a truncated 0x30, which broke the OUTER parameters
	// and was refused one level too early as "RSASSA-PSS parameters"; the
	// message assertion is what showed this case had never reached the MGF1
	// check it is named for.
	badMGF := must(t, pssParams{
		Hash: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		MGF:  pkix.AlgorithmIdentifier{Algorithm: oidMGF1, Parameters: asn1.RawValue{FullBytes: must(t, 5)}},
	})
	for _, tc := range []struct {
		name   string
		params []byte
		class  error
		says   string
	}{
		{"no parameters", nil, ErrMalformed, "without parameters"},
		{"parameters that are not DER", []byte{0x30}, ErrMalformed, "RSASSA-PSS parameters"},
		{"a SHA-1 hash", pss(t, oidSHA1, oidMGF1, oidSHA1, 20, 1), ErrUnsupported, "RSASSA-PSS hash"},
		{"a hash that is not the digest's", pss(t, oidSHA384, oidMGF1, oidSHA384, 48, 1), ErrMalformed, "RSASSA-PSS uses SHA-384"},
		{"a mask generation that is not MGF1", pss(t, oidSHA256, oidSHA256, oidSHA256, 32, 1), ErrUnsupported, "mask generation"},
		{"MGF1 parameters that are not DER", badMGF, ErrMalformed, "MGF1 hash"},
		{"MGF1 over SHA-1", pss(t, oidSHA256, oidMGF1, oidSHA1, 32, 1), ErrUnsupported, "MGF1 hash"},
		{"MGF1 over another hash", pss(t, oidSHA256, oidMGF1, oidSHA512, 32, 1), ErrUnsupported, "MGF1 uses SHA-512"},
		{"a salt that is not the hash's length", pss(t, oidSHA256, oidMGF1, oidSHA256, 20, 1), ErrUnsupported, "salt of 20 bytes"},
		{"a trailer other than 1", pss(t, oidSHA256, oidMGF1, oidSHA256, 32, 2), ErrMalformed, "trailer field 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantRefusal(t, checkPSS(tc.params, h), tc.class, tc.says)
		})
	}
	// ⛔ The control: the parameters OpenSSL wrote for rsa-pss are accepted,
	// so the refusals above are about what they change and not about PSS.
	if err := checkPSS(pss(t, oidSHA256, oidMGF1, oidSHA256, 32, 1), h); err != nil {
		t.Fatalf("SHA-256, MGF1-SHA-256, salt 32: %v", err)
	}
}
