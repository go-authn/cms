// SPDX-License-Identifier: BSD-3-Clause

package cms

import (
	"encoding/asn1"
	"testing"
)

// Security audit 2026-11-21. A signature made WITH signed attributes over
// content C is re-packed, without the key, as a SignedData WITHOUT signed
// attributes whose attached id-data content is the DER of those attributes.
// Verify must not name the signer for content the signer never signed as
// content.
func TestSecAudit5SignedAttrsReplayedAsContent(t *testing.T) {
	for _, c := range signCases() {
		t.Run(c.name, func(t *testing.T) {
			o := c.options(t)
			o.NoSignedAttrs, o.Detached = false, false
			orig, err := Sign([]byte("pay 10 EUR to alice"), o)
			if err != nil {
				t.Skip(err)
			}
			sd, err := Parse(orig)
			if err != nil {
				t.Fatal(err)
			}
			s := sd.Signers[0]
			forgedContent := append([]byte(nil), s.signedAttrsDER...)
			forgedContent[0] = 0x31

			cert := o.Certificate
			serial, _ := asn1.Marshal(cert.SerialNumber)
			digAlg, err := asn1.Marshal(s.DigestAlgorithm)
			if err != nil {
				t.Fatal(err)
			}
			sigAlg, err := asn1.Marshal(s.SignatureAlgorithm)
			if err != nil {
				t.Fatal(err)
			}
			signerInfo := der(0x30,
				[]byte{0x02, 0x01, 0x01},
				der(0x30, cert.RawIssuer, serial),
				digAlg,
				sigAlg,
				der(0x04, s.Signature),
			)
			body := der(0x30,
				[]byte{0x02, 0x01, 0x01},
				der(0x31, digAlg),
				der(0x30, oidDER(oidData), der(0xA0, der(0x04, forgedContent))),
				der(0xA0, cert.Raw),
				der(0x31, signerInfo),
			)
			forged := der(0x30, oidDER(oidSignedData), der(0xA0, body))

			fsd, err := Parse(forged)
			if err != nil {
				t.Logf("refused at Parse: %v", err)
				return
			}
			certs, err := fsd.Verify(nil)
			if err == nil {
				t.Fatalf("FORGERY ACCEPTED: Verify names signer %q for %d bytes of content (first byte %#x) it never signed as content",
					certs[0].Subject.CommonName, len(fsd.Content), fsd.Content[0])
			}
			t.Logf("refused at Verify: %v", err)
		})
	}
}

// The guard's own boundary: only a DER SET OF Attribute carrying BOTH the
// content-type and message-digest attributes is refused as content. A SET that
// lacks one of them, a non-SET, and trailing bytes are ordinary content.
func TestLooksLikeSignedAttrs(t *testing.T) {
	attr := func(oid asn1.ObjectIdentifier) []byte {
		o, _ := asn1.Marshal(oid)
		return der(0x30, o, der(0x31, der(0x04, []byte{1})))
	}
	ct, md := attr(oidContentType), attr(oidMessageDigest)
	other := attr(asn1.ObjectIdentifier{1, 2, 3})
	for _, c := range []struct {
		name string
		in   []byte
		want bool
	}{
		{"both", der(0x31, ct, md), true},
		{"both reversed", der(0x31, md, ct), true},
		{"both plus other", der(0x31, ct, other, md), true},
		{"content-type only", der(0x31, ct), false},
		{"message-digest only", der(0x31, md), false},
		{"neither", der(0x31, other), false},
		{"sequence not set", der(0x30, ct, md), false},
		{"trailing byte", append(der(0x31, ct, md), 0), false},
		{"empty", nil, false},
		{"text", []byte("pay 10 EUR to alice"), false},
	} {
		if got := looksLikeSignedAttrs(c.in); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
