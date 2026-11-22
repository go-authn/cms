// SPDX-License-Identifier: BSD-3-Clause

package cms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"sort"
	"testing"
	"time"
)

// forgeSigningTimes signs, with the test's own Ed25519 key, a SignedData
// whose signed attributes are content-type, message-digest and the given
// signing-time attributes (each already an encoded attribute). Everything
// else is what RFC 5652 asks for, so the only fault is the signing-time one.
func forgeSigningTimes(t *testing.T, times ...[]byte) []byte {
	t.Helper()
	o := signCase{"ed", "ed25519", SignOptions{Hash: crypto.SHA512}}.options(t)
	content := []byte("pay 10 EUR to alice")
	orig, err := Sign(content, o)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(orig)
	if err != nil {
		t.Fatal(err)
	}
	s := sd.Signers[0]
	sum := sha512.Sum512(content)
	attrs := [][]byte{
		attribute(oidContentType, oidDER(oidData)),
		attribute(oidMessageDigest, der(0x04, sum[:])),
	}
	attrs = append(attrs, times...)
	sort.Slice(attrs, func(i, j int) bool { return bytes.Compare(attrs[i], attrs[j]) < 0 })
	set := der(0x31, attrs...)
	sig, err := o.Signer.Sign(rand.Reader, set, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	cert := o.Certificate
	serial, _ := asn1.Marshal(cert.SerialNumber)
	digAlg, _ := asn1.Marshal(s.DigestAlgorithm)
	sigAlg, _ := asn1.Marshal(s.SignatureAlgorithm)
	signed := append([]byte(nil), set...)
	signed[0] = 0xA0
	signerInfo := der(0x30,
		[]byte{0x02, 0x01, 0x01},
		der(0x30, cert.RawIssuer, serial),
		digAlg,
		signed,
		sigAlg,
		der(0x04, sig),
	)
	body := der(0x30,
		[]byte{0x02, 0x01, 0x01},
		der(0x31, digAlg),
		der(0x30, oidDER(oidData), der(0xA0, der(0x04, content))),
		der(0xA0, cert.Raw),
		der(0x31, signerInfo),
	)
	return der(0x30, oidDER(oidSignedData), der(0xA0, body))
}

func verifyForged(t *testing.T, msg []byte) error {
	t.Helper()
	sd, err := Parse(msg)
	if err != nil {
		return err
	}
	_, err = sd.Verify(nil)
	return err
}

// RFC 5652 §11.3: a signing-time attribute has exactly one value, and the
// SignedAttributes MUST NOT include several signing-time attributes. §11.1 and
// §11.2 say the same of content-type and message-digest, which are refused; a
// reader of SignedAttrs that takes the first signing time and one that takes
// the last must not both be right about a message this package verified.
func TestSigningTimeIsSingleValuedAndSingleInstance(t *testing.T) {
	t1 := timeDER(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	t2 := timeDER(time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC))

	// Control: one signing-time with one value verifies.
	if err := verifyForged(t, forgeSigningTimes(t, attribute(oidSigningTime, t1))); err != nil {
		t.Fatalf("a well-formed signing-time was refused: %v", err)
	}
	// Control: no signing-time verifies.
	if err := verifyForged(t, forgeSigningTimes(t)); err != nil {
		t.Fatalf("no signing-time was refused: %v", err)
	}

	// Two attributes of the type.
	err := verifyForged(t, forgeSigningTimes(t, attribute(oidSigningTime, t1), attribute(oidSigningTime, t2)))
	if err == nil {
		t.Error("two signing-time attributes were accepted")
	} else if !errors.Is(err, ErrMalformed) {
		t.Errorf("two signing-time attributes: %v", err)
	}

	// One attribute with two values.
	two := der(0x30, oidDER(oidSigningTime), der(0x31, t1, t2))
	if err := verifyForged(t, forgeSigningTimes(t, two)); err == nil {
		t.Error("a signing-time attribute with two values was accepted")
	}
	// One attribute with no value.
	none := der(0x30, oidDER(oidSigningTime), der(0x31))
	if err := verifyForged(t, forgeSigningTimes(t, none)); err == nil {
		t.Error("a signing-time attribute with no value was accepted")
	}
}
