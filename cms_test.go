package cms

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEveryOpenSSLFixtureVerifies is the positive half, and it needs no
// openssl at run time: the fixtures are committed. Each returns exactly one
// signing certificate, and it is the one OpenSSL was told to sign with.
func TestEveryOpenSSLFixtureVerifies(t *testing.T) {
	content := read(t, "content")
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			sd, err := Parse(read(t, f.name+".der"))
			if err != nil {
				t.Fatal(err)
			}
			supplied := content
			if attached(f) {
				if !bytes.Equal(sd.Content, content) {
					t.Fatalf("attached content %q", sd.Content)
				}
				supplied = nil
			} else if sd.Content != nil {
				t.Fatalf("a detached fixture carried content %q", sd.Content)
			}
			certs, err := sd.Verify(supplied)
			if err != nil {
				t.Fatal(err)
			}
			if len(certs) != 1 || !strings.HasSuffix(certs[0].Subject.CommonName, f.key) {
				t.Fatalf("signed by %v, want the %s test certificate", certs, f.key)
			}
		})
	}
}

// TestBothSignerIdentifierFormsAreRead pins §5.3's "MUST support the
// reception of the issuerAndSerialNumber and subjectKeyIdentifier forms":
// the default fixture names its signer one way and -keyid the other.
func TestBothSignerIdentifierFormsAreRead(t *testing.T) {
	ias, err := Parse(read(t, "rsa-detached.der"))
	if err != nil {
		t.Fatal(err)
	}
	if ias.Signers[0].IssuerAndSerial == nil || ias.Signers[0].SubjectKeyID != nil {
		t.Fatalf("rsa-detached: %+v", ias.Signers[0])
	}
	ski, err := Parse(read(t, "rsa-keyid.der"))
	if err != nil {
		t.Fatal(err)
	}
	if ski.Signers[0].SubjectKeyID == nil || ski.Signers[0].IssuerAndSerial != nil {
		t.Fatalf("rsa-keyid: %+v", ski.Signers[0])
	}
}

// ---- the builder: OpenSSL's output, changed in one place ----

// rebuild parses a fixture into the ASN.1 shapes, lets mutate change them,
// and encodes the ContentInfo again.
//
// ⛔ It first proves it can do nothing: with no mutation the rebuilt bytes
// must EQUAL the fixture. A builder that silently re-encoded some other field
// would make every negative test below a test of the builder's change rather
// than of the one it names.
func rebuild(t *testing.T, name string, mutate func(*signedDataASN1)) []byte {
	t.Helper()
	encode := func(m func(*signedDataASN1)) []byte {
		der := read(t, name)
		var ci contentInfo
		if _, err := asn1.Unmarshal(der, &ci); err != nil {
			t.Fatal(err)
		}
		var sd signedDataASN1
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
			t.Fatal(err)
		}
		if m != nil {
			m(&sd)
		}
		inner, err := asn1.Marshal(sd)
		if err != nil {
			t.Fatal(err)
		}
		out, err := asn1.Marshal(struct {
			Type    asn1.ObjectIdentifier
			Content asn1.RawValue
		}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := encode(nil); !bytes.Equal(got, read(t, name)) {
		t.Fatalf("rebuild is not the identity on %s: the builder changes bytes it was not asked to", name)
	}
	return encode(mutate)
}

// attrsOf returns signer i's signed attributes, decoded.
func attrsOf(t *testing.T, sd *signedDataASN1) []Attribute {
	t.Helper()
	a, err := readAttributes(sd.SignerInfos[0].SignedAttrs.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// setAttrs replaces the first signer's signed attributes.
func setAttrs(t *testing.T, sd *signedDataASN1, attrs []Attribute) {
	t.Helper()
	var body []byte
	for _, a := range attrs {
		b, err := asn1.Marshal(struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue
		}{a.Type, asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: bytes.Join(a.Values, nil)}})
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, b...)
	}
	full, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatal(err)
	}
	sd.SignerInfos[0].SignedAttrs = asn1.RawValue{FullBytes: full}
}

func oidValue(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	b, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func without(attrs []Attribute, t asn1.ObjectIdentifier) []Attribute {
	var out []Attribute
	for _, a := range attrs {
		if !a.Type.Equal(t) {
			out = append(out, a)
		}
	}
	return out
}

func find(attrs []Attribute, t asn1.ObjectIdentifier) Attribute {
	for _, a := range attrs {
		if a.Type.Equal(t) {
			return a
		}
	}
	return Attribute{}
}

// TestWhatTheRFCForbidsIsRefusedByName drives every rule this package
// enforces through an OpenSSL signature changed in exactly one place, and
// asserts the error CLASS and the MESSAGE — never "some error". Several of
// these mutations also break the signature, so a test that only asked for an
// error would pass for the wrong reason: the message is what proves the named
// check fired, and fired first.
func TestWhatTheRFCForbidsIsRefusedByName(t *testing.T) {
	content := read(t, "content")
	for _, tc := range []struct {
		name    string
		fixture string
		mutate  func(*testing.T, *signedDataASN1)
		class   error
		says    string
	}{
		{"two message-digest attributes (§11.2)", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) {
				a := attrsOf(t, sd)
				setAttrs(t, sd, append(a, find(a, oidMessageDigest)))
			}, ErrMalformed, "more than one message-digest attribute"},
		{"a message-digest with two values (§11.2)", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) {
				a := attrsOf(t, sd)
				md := find(a, oidMessageDigest)
				md.Values = append(md.Values, md.Values[0])
				setAttrs(t, sd, append(without(a, oidMessageDigest), md))
			}, ErrMalformed, "message-digest attribute has 2 values, not one"},
		{"no message-digest (§5.3)", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) {
				setAttrs(t, sd, without(attrsOf(t, sd), oidMessageDigest))
			}, ErrMalformed, "no message-digest attribute"},
		{"two content-type attributes (§11.1)", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) {
				a := attrsOf(t, sd)
				setAttrs(t, sd, append(a, find(a, oidContentType)))
			}, ErrMalformed, "more than one content-type attribute"},
		{"no content-type (§5.3)", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) {
				setAttrs(t, sd, without(attrsOf(t, sd), oidContentType))
			}, ErrMalformed, "no content-type attribute"},
		{"a signed content type that is not the content's (§5.6)", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) {
				a := without(attrsOf(t, sd), oidContentType)
				setAttrs(t, sd, append(a, Attribute{oidContentType, [][]byte{oidValue(t, oidSignedData)}}))
			}, ErrInvalid, "the signed content type is"},
		{"a present but empty signedAttrs (SIZE 1..MAX)", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) { setAttrs(t, sd, nil) },
			ErrMalformed, "signedAttrs is present and empty"},
		{"SHA-1, refused by name", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) {
				sd.SignerInfos[0].DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oidSHA1}
			}, ErrUnsupported, "SHA-1 digests are not accepted"},
		{"an unknown digest", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) {
				sd.SignerInfos[0].DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}
			}, ErrUnsupported, "digest algorithm 1.2.3"},
		{"an unknown signature algorithm", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) {
				sd.SignerInfos[0].SignatureAlgorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}
			}, ErrUnsupported, "signature algorithm 1.2.3"},
		{"a signature OID whose hash is not the digest's", "rsa-sha384.der",
			func(t *testing.T, sd *signedDataASN1) {
				sd.SignerInfos[0].SignatureAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA}
			}, ErrMalformed, "but the digest algorithm is SHA-384"},
		{"no certificate for the signer", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) { sd.Certificates = asn1.RawValue{} },
			ErrUnsupported, "certificate is not in the SignedData"},
		{"no signers", "rsa-detached.der",
			func(t *testing.T, sd *signedDataASN1) { sd.SignerInfos = nil },
			ErrInvalid, "no signers"},
		// ⛔ End to end on OpenSSL's own PSS signature, one parameter
		// changed: the PSS unit tests call checkPSS directly, which proved
		// the checks and never that Verify reaches them.
		{"RSASSA-PSS with a salt other than the hash's length", "rsa-pss.der",
			func(t *testing.T, sd *signedDataASN1) {
				sd.SignerInfos[0].SignatureAlgorithm.Parameters = asn1.RawValue{
					FullBytes: pss(t, oidSHA256, oidMGF1, oidSHA256, 20, 1)}
			}, ErrUnsupported, "salt of 20 bytes"},
		{"no signed attributes over content that is not id-data (§5.3)", "rsa-noattr.der",
			func(t *testing.T, sd *signedDataASN1) {
				sd.EncapContentInfo.EContentType = oidSignedData
			}, ErrMalformed, "without signed attributes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der := rebuild(t, tc.fixture, func(sd *signedDataASN1) { tc.mutate(t, sd) })
			sd, err := Parse(der)
			if err == nil {
				_, err = sd.Verify(content)
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if !errorsIs(err, tc.class) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("refused for the wrong reason:\n  got  %v\n  want %v containing %q", err, tc.class, tc.says)
			}
		})
	}
}

// TestTheContentIsSuppliedExactlyOnce pins Verify's two refusals about where
// the signed bytes come from: never both attached and supplied, never neither.
func TestTheContentIsSuppliedExactlyOnce(t *testing.T) {
	content := read(t, "content")
	attachedSD, err := Parse(read(t, "rsa-attached.der"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attachedSD.Verify(content); !errorsIs(err, ErrMalformed) ||
		!strings.Contains(err.Error(), "attached and was also supplied") {
		t.Fatalf("attached and supplied: %v", err)
	}
	detachedSD, err := Parse(read(t, "rsa-detached.der"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := detachedSD.Verify(nil); !errorsIs(err, ErrMalformed) ||
		!strings.Contains(err.Error(), "needs the content it signed") {
		t.Fatalf("detached without content: %v", err)
	}
}

// TestWhatParseRefuses covers the structural refusals: trailing bytes, an
// input past the size bound, a ContentInfo that is not signed-data, and
// bytes that are not DER at all.
func TestWhatParseRefuses(t *testing.T) {
	good := read(t, "rsa-detached.der")
	other, err := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{0x04, 0x00}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		der   []byte
		class error
		says  string
	}{
		{"a trailing byte", append(append([]byte(nil), good...), 0), ErrMalformed, "trailing byte"},
		{"not DER", []byte("not a signature"), ErrMalformed, "ContentInfo"},
		{"a ContentInfo that is not signed-data", other, ErrUnsupported, "is not signed-data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.der)
			if !errorsIs(err, tc.class) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("got %v, want %v containing %q", err, tc.class, tc.says)
			}
		})
	}

	t.Run("an input past the size bound", func(t *testing.T) {
		defer func(old int) { maxInput = old }(maxInput)
		maxInput = len(good) - 1
		if _, err := Parse(good); !errorsIs(err, ErrMalformed) || !strings.Contains(err.Error(), "past the limit") {
			t.Fatalf("got %v", err)
		}
		// ⛔ The control: one byte more and the same input is read.
		maxInput = len(good)
		if _, err := Parse(good); err != nil {
			t.Fatalf("an input exactly at the bound was refused: %v", err)
		}
	})
}
