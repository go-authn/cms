package cms

import (
	"bytes"
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
	b.WriteString("|content|")
	b.Write(effective)
	for i, s := range sd.Signers {
		b.WriteString("|attrs|")
		b.Write(s.signedAttrsDER)
		b.WriteString("|sig|")
		b.Write(s.Signature)
		b.WriteString("|key|")
		b.Write(certs[i].RawSubjectPublicKeyInfo)
	}
	return b.String()
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
