package cms

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// classified reports whether err wraps exactly one of the three classes.
//
// ⛔ THIS IS AN INVARIANT, NOT JUST "NO PANIC". A caller acts on the class:
// ErrMalformed says "not a signature", ErrUnsupported "a signature I cannot
// check", ErrInvalid "a signature that does not hold". An error that escapes
// unclassified — a decoder's message passed up without %w — would leave a
// caller unable to tell a forgery from a format it merely does not speak, and
// RFC 5652 §5.1 asks for exactly that distinction.
func classified(err error) bool {
	n := 0
	for _, c := range []error{ErrMalformed, ErrUnsupported, ErrInvalid} {
		if errors.Is(err, c) {
			n++
		}
	}
	return n == 1
}

func seed(f *testing.F) [][]byte {
	f.Helper()
	var out [][]byte
	for _, fx := range fixtures {
		der, err := os.ReadFile(filepath.Join("testdata", fx.name+".der"))
		if err != nil {
			f.Fatalf("a seed named in fixtures is missing: %v", err)
		}
		f.Add(der)
		out = append(out, der)
	}
	return out
}

// FuzzParse: any input either parses or is refused with a classified error.
func FuzzParse(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, der []byte) {
		_, err := Parse(der)
		if err != nil && !classified(err) {
			t.Fatalf("an unclassified refusal: %v", err)
		}
	})
}

// bound is everything a signature cryptographically commits to, for every
// signer: what was signed (signed attributes, or the content when there are
// none), the signature, and the public key that checks it.
//
// ⭐ WHY THIS AND NOT "THE INPUT IS A FIXTURE". Plenty of mutations
// legitimately still verify: DigestAlgorithms is advisory (§5.1), version
// fields are not checked, and an embedded certificate's subject or extensions
// can change without touching its key — this package does not validate the
// chain (§5.6), and must not pretend to. What must NEVER verify is a change to
// anything the signature binds. So the invariant compares the bound tuple, not
// the bytes: an accepted input whose tuple matches no OpenSSL original is a
// forgery, and fails.
func bound(sd *SignedData, supplied []byte) string {
	var b bytes.Buffer
	certs, err := sd.Verify(supplied)
	if err != nil {
		return ""
	}
	// ⛔ The content that was VERIFIED: for an attached signature that is
	// sd.Content, not the nil the caller supplied. A first draft wrote the
	// supplied argument, which left an attached signature's content out of
	// the tuple entirely.
	effective := supplied
	if effective == nil {
		effective = sd.Content
	}
	// ⛔ EVERY FIELD IS LENGTH-PREFIXED. The first version joined them with
	// "|tag|" separators, and binary fields can contain those bytes, so two
	// different tuples could in principle serialise to one string and a
	// forgery be classed as an original. Review found it by reading.
	field := func(p []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		b.Write(n[:])
		b.Write(p)
	}
	field(effective)
	for i, s := range sd.Signers {
		field(s.signedAttrsDER)
		field(s.Signature)
		field(certs[i].RawSubjectPublicKeyInfo)
	}
	return b.String()
}

// primitiveAttrs is rsa-detached with its signedAttrs tag turned from the
// constructed 0xA0 into the primitive 0x80: one bit. It VERIFIED before
// readSigner checked IsCompound, which this target calls a forgery — and the
// fuzzer never produced it. External review did. It is seeded here so every
// run asks again, rather than hoping a mutator flips that one bit.
func primitiveAttrs(der []byte) ([]byte, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, err
	}
	var sd signedDataASN1
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, err
	}
	fb := append([]byte(nil), sd.SignerInfos[0].SignedAttrs.FullBytes...)
	fb[0] = 0x80
	sd.SignerInfos[0].SignedAttrs = asn1.RawValue{FullBytes: fb}
	inner, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
}

// FuzzVerify drives the whole path — Parse, then Verify — and asserts two
// things: every refusal is classified, and nothing verifies unless what its
// signature binds is exactly what OpenSSL signed.
//
// ⚠ One known gap, stated rather than hidden: ECDSA signatures are malleable
// ((r, s) and (r, n−s) both verify), so an input could in principle carry a
// different signature over the same bytes. Random byte mutation does not
// compute n−s, and crypto/ecdsa refuses a non-minimal encoding, so the fuzzer
// is not expected to find one; if it ever does, it is a malleability report,
// not a forgery of content, and the failure message says which signer.
func FuzzVerify(f *testing.F) {
	originals := seed(f)
	flipped, err := primitiveAttrs(originals[0])
	if err != nil {
		f.Fatal(err)
	}
	f.Add(flipped)
	content, err := os.ReadFile(filepath.Join("testdata", "content"))
	if err != nil {
		f.Fatal(err)
	}
	contentFor := func(sd *SignedData) []byte {
		if sd.Content != nil {
			return nil // attached: Verify reads it from the container
		}
		return content
	}
	legit := map[string]bool{}
	for _, der := range originals {
		sd, err := Parse(der)
		if err != nil {
			f.Fatalf("an OpenSSL fixture does not parse: %v", err)
		}
		key := bound(sd, contentFor(sd))
		if key == "" {
			f.Fatal("an OpenSSL fixture does not verify")
		}
		legit[key] = true
	}

	f.Fuzz(func(t *testing.T, der []byte) {
		sd, err := Parse(der)
		if err != nil {
			if !classified(err) {
				t.Fatalf("Parse: an unclassified refusal: %v", err)
			}
			return
		}
		if _, err := sd.Verify(contentFor(sd)); err != nil {
			if !classified(err) {
				t.Fatalf("Verify: an unclassified refusal: %v", err)
			}
			return
		}
		if key := bound(sd, contentFor(sd)); !legit[key] {
			t.Fatalf("FORGERY: an input verified whose signed bytes, signature or key "+
				"match no OpenSSL original (%d signer(s))", len(sd.Signers))
		}
	})
}
