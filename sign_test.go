package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A signing identity: key, self-signed certificate.
type identity struct {
	key  crypto.Signer
	cert *x509.Certificate
}

var (
	identOnce sync.Once
	idents    map[string]identity
)

// identities makes the keys once: an RSA key costs real time, and nothing
// here needs a fresh one per case. Nothing is written to disk.
func identities(t *testing.T) map[string]identity {
	t.Helper()
	identOnce.Do(func() {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		idents = map[string]identity{}
		for name, k := range map[string]crypto.Signer{"rsa": rsaKey, "ec": ecKey, "ed25519": edKey} {
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(0x1234abcd),
				Subject:      pkix.Name{CommonName: "cms sign test " + name},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(24 * time.Hour),
				SubjectKeyId: []byte{1, 2, 3, 4},
			}
			raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
			if err != nil {
				panic(err)
			}
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				panic(err)
			}
			idents[name] = identity{k, c}
		}
	})
	return idents
}

type signCase struct {
	name string
	key  string
	opts SignOptions
}

func (c signCase) options(t *testing.T) SignOptions {
	id := identities(t)[c.key]
	o := c.opts
	o.Signer, o.Certificate = id.key, id.cert
	return o
}

// signCases is every combination the package claims: key family and padding,
// digest, attached or detached, and which attributes ride along.
func signCases() []signCase {
	type shape struct {
		name string
		f    func(*SignOptions)
	}
	shapes := []shape{
		{"attrs", func(o *SignOptions) {}},
		{"attrs+time+certv2", func(o *SignOptions) {
			o.SigningTime = time.Date(2026, 11, 20, 12, 30, 45, 0, time.UTC)
			o.SigningCertificateV2 = true
		}},
		{"noattr", func(o *SignOptions) { o.NoSignedAttrs = true }},
	}
	type keyKind struct {
		name, key string
		pss       bool
		hashes    []crypto.Hash
	}
	all := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}
	kinds := []keyKind{
		{"rsa", "rsa", false, all},
		{"rsa-pss", "rsa", true, all},
		{"ecdsa", "ec", false, all},
		{"ed25519", "ed25519", false, []crypto.Hash{crypto.SHA512}},
	}
	var out []signCase
	for _, k := range kinds {
		for _, h := range k.hashes {
			for _, detached := range []bool{true, false} {
				for _, s := range shapes {
					o := SignOptions{Hash: h, PSS: k.pss, Detached: detached}
					s.f(&o)
					if k.key == "ed25519" && o.NoSignedAttrs {
						continue // refused: see TestSignRefusals
					}
					mode := "attached"
					if detached {
						mode = "detached"
					}
					out = append(out, signCase{fmt.Sprintf("%s/%v/%s/%s", k.name, h, mode, s.name), k.key, o})
				}
			}
		}
	}
	return out
}

// opensslVerify is OpenSSL's verdict on der: nil when `cms -verify` accepts.
func opensslVerify(ossl, dir string, der, content []byte, isAttached bool) error {
	sigPath, contentPath := filepath.Join(dir, "sig.der"), filepath.Join(dir, "content")
	if err := os.WriteFile(sigPath, der, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(contentPath, content, 0o644); err != nil {
		return err
	}
	args := []string{"cms", "-verify", "-noverify", "-binary", "-inform", "DER",
		"-in", sigPath, "-out", filepath.Join(dir, "out")}
	if !isAttached {
		args = append(args, "-content", contentPath)
	}
	if out, err := exec.Command(ossl, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// TestSignedByUsJudgedByOpenSSL is the oracle for signing: every combination
// Sign produces is handed to `openssl cms -verify` AND to this package's
// Verify, untouched (both must accept) and tampered (both must refuse).
// ⛔ The reader's fixtures were made by OpenSSL; these are made by the code
// under test, so the verdict that matters is OpenSSL's, and it is asked both
// ways — a judge shown only good signatures cannot tell a verifier from one
// that accepts everything.
func TestSignedByUsJudgedByOpenSSL(t *testing.T) {
	ossl := openssl(t)
	dir := t.TempDir()
	for _, c := range signCases() {
		t.Run(c.name, func(t *testing.T) {
			o := c.options(t)
			der, err := Sign([]byte(theContent), o)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range variants(der) {
				theirs := opensslVerify(ossl, dir, v.der, v.content, !o.Detached)
				ours := verifyBytes(v.der, v.content, !o.Detached)
				if (ours == nil) != (theirs == nil) {
					t.Fatalf("%s: openssl says %v, this package says %v", v.name, theirs, ours)
				}
				// A content argument no attached verify reads is no tampering.
				mustVerify := v.name == "untouched" || (!o.Detached && v.name == "content-changed")
				if mustVerify != (ours == nil) {
					t.Fatalf("%s: verdict %v, but only the untouched signature may verify", v.name, ours)
				}
			}
		})
	}
}

// TestSignRoundTrip: what Parse reads is what Sign was asked for.
func TestSignRoundTrip(t *testing.T) {
	for _, c := range signCases() {
		t.Run(c.name, func(t *testing.T) {
			o := c.options(t)
			content := []byte("round trip " + c.name)
			der, err := Sign(content, o)
			if err != nil {
				t.Fatal(err)
			}
			sd, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			if sd.Version != 1 || !sd.ContentType.Equal(oidData) {
				t.Fatalf("version %d, content type %v", sd.Version, sd.ContentType)
			}
			if o.Detached == (sd.Content != nil) || (!o.Detached && !bytes.Equal(sd.Content, content)) {
				t.Fatalf("detached=%v but content is %q", o.Detached, sd.Content)
			}
			if len(sd.Certificates) != 1 || !sd.Certificates[0].Equal(o.Certificate) {
				t.Fatalf("certificates: %v", sd.Certificates)
			}
			if len(sd.Signers) != 1 {
				t.Fatalf("%d signers", len(sd.Signers))
			}
			s := sd.Signers[0]
			if s.Version != 1 || s.IssuerAndSerial == nil || s.IssuerAndSerial.Serial.Cmp(o.Certificate.SerialNumber) != 0 ||
				!bytes.Equal(s.IssuerAndSerial.RawIssuer, o.Certificate.RawIssuer) {
				t.Fatalf("signer identifier: %+v", s)
			}
			if (s.SignedAttrs == nil) != o.NoSignedAttrs {
				t.Fatalf("signed attrs %v with NoSignedAttrs=%v", s.SignedAttrs, o.NoSignedAttrs)
			}
			want := 0
			if !o.NoSignedAttrs {
				want = 2
				if !o.SigningTime.IsZero() {
					want++
				}
				if o.SigningCertificateV2 {
					want++
				}
			}
			if len(s.SignedAttrs) != want {
				t.Fatalf("%d signed attributes, want %d", len(s.SignedAttrs), want)
			}
			var certs []*x509.Certificate
			if o.Detached {
				certs, err = sd.Verify(content)
			} else {
				certs, err = sd.Verify(nil)
			}
			if err != nil || len(certs) != 1 || !certs[0].Equal(o.Certificate) {
				t.Fatalf("verify: %v %v", certs, err)
			}
		})
	}
}

// TestSignedAttrsAreDER: the SET OF is sorted by encoding and every
// attribute value is a single, definite DER element.
func TestSignedAttrsAreDER(t *testing.T) {
	c := signCase{"x", "rsa", SignOptions{
		SigningTime: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), SigningCertificateV2: true, Detached: true,
	}}
	der, err := Sign([]byte("x"), c.options(t))
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	set := sd.Signers[0].signedAttrsDER
	if set[0] != 0xA0 {
		t.Fatalf("signedAttrs tag %#x, want 0xA0", set[0])
	}
	var body asn1.RawValue
	if _, err := asn1.Unmarshal(set, &body); err != nil {
		t.Fatal(err)
	}
	var prev []byte
	n := 0
	for b := body.Bytes; len(b) > 0; n++ {
		var one asn1.RawValue
		var err error
		b, err = asn1.Unmarshal(b, &one)
		if err != nil {
			t.Fatal(err)
		}
		if prev != nil && bytes.Compare(prev, one.FullBytes) >= 0 {
			t.Fatalf("attribute %d is not after attribute %d in DER order", n, n-1)
		}
		prev = one.FullBytes
	}
	if n != 4 {
		t.Fatalf("%d attributes", n)
	}
}

// TestSignTamperEachSignedAttribute: changing one byte of any signed
// attribute value inside the container breaks Verify.
func TestSignTamperEachSignedAttribute(t *testing.T) {
	content := []byte("tamper me")
	o := signCase{"x", "ec", SignOptions{
		SigningTime: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), SigningCertificateV2: true, Detached: true,
	}}.options(t)
	der, err := Sign(content, o)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range sd.Signers[0].SignedAttrs {
		v := a.Values[0]
		// The LAST occurrence: the content-type value is the same OID that
		// eContentType already spelled earlier in the container.
		at := bytes.LastIndex(der, v)
		if at < 0 {
			t.Fatalf("attribute %v value is not in the container", a.Type)
		}
		t.Run(a.Type.String(), func(t *testing.T) {
			bad := append([]byte(nil), der...)
			bad[at+len(v)-1] ^= 1
			if err := verifyBytes(bad, content, false); err == nil {
				t.Fatal("a changed signed attribute still verifies")
			}
		})
	}
	// And the signature, the content and the signer's certificate identity.
	bad := append([]byte(nil), der...)
	bad[len(bad)-1] ^= 1
	if verifyBytes(bad, content, false) == nil {
		t.Fatal("changed signature verifies")
	}
	if verifyBytes(der, []byte("tamper mf"), false) == nil {
		t.Fatal("changed content verifies")
	}
}

// TestSigningCertificateV2: RFC 5035 §5.4.1's value, field by field.
func TestSigningCertificateV2(t *testing.T) {
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
		o := signCase{"x", "rsa", SignOptions{SigningCertificateV2: true, Hash: h}}.options(t)
		der, err := Sign([]byte("x"), o)
		if err != nil {
			t.Fatal(err)
		}
		sd, err := Parse(der)
		if err != nil {
			t.Fatal(err)
		}
		v, err := singleValue(sd.Signers[0].SignedAttrs, oidSigningCertV2, "signing-certificate-v2")
		if err != nil {
			t.Fatal(err)
		}
		var sc struct {
			Certs []asn1.RawValue
		}
		if err := unmarshalAll(v, &sc, "SigningCertificateV2"); err != nil || len(sc.Certs) != 1 {
			t.Fatalf("%v %d", err, len(sc.Certs))
		}
		var id struct {
			Alg    pkix.AlgorithmIdentifier `asn1:"optional"`
			Hash   []byte
			Issuer struct {
				Names  asn1.RawValue
				Serial *big.Int
			}
		}
		if err := unmarshalAll(sc.Certs[0].FullBytes, &id, "ESSCertIDv2"); err != nil {
			t.Fatal(err)
		}
		hh := h.New()
		hh.Write(o.Certificate.Raw)
		if !bytes.Equal(id.Hash, hh.Sum(nil)) {
			t.Fatal("certHash is not the hash of the certificate")
		}
		if id.Issuer.Serial.Cmp(o.Certificate.SerialNumber) != 0 {
			t.Fatal("issuerSerial serial")
		}
		// directoryName [4] holding the issuer Name exactly as encoded.
		want := der4(o.Certificate.RawIssuer)
		if !bytes.Equal(id.Issuer.Names.Bytes, want) {
			t.Fatalf("GeneralNames %x, want %x", id.Issuer.Names.Bytes, want)
		}
		// DEFAULT id-sha256 is omitted in DER, and written for anything else.
		if (h == crypto.SHA256) != (len(id.Alg.Algorithm) == 0) {
			t.Fatalf("hashAlgorithm %v for %v", id.Alg.Algorithm, h)
		}
		if h != crypto.SHA256 && !id.Alg.Algorithm.Equal(oidSHA384) {
			t.Fatalf("hashAlgorithm %v", id.Alg.Algorithm)
		}
	}
}

func der4(name []byte) []byte { return der(0xA4, name) }

// TestSigningTimeEncoding: UTCTime for 1950..2049, GeneralizedTime outside
// (§11.3), always UTC and to the second.
func TestSigningTimeEncoding(t *testing.T) {
	cest := time.FixedZone("CEST", 2*3600)
	for _, c := range []struct {
		t    time.Time
		want string
	}{
		{time.Date(2026, 11, 20, 14, 30, 45, 999, cest), "\x17\x0d261120123045Z"},
		{time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC), "\x17\x0d500101000000Z"},
		{time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), "\x17\x0d491231235959Z"},
		{time.Date(1949, 12, 31, 23, 59, 59, 0, time.UTC), "\x18\x0f19491231235959Z"},
		{time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC), "\x18\x0f20500101000000Z"},
	} {
		if got := string(timeDER(c.t)); got != c.want {
			t.Errorf("%v: %q, want %q", c.t, got, c.want)
		}
	}
	// And a generalized one survives the whole container and the reader.
	o := signCase{"x", "ec", SignOptions{SigningTime: time.Date(2060, 5, 6, 7, 8, 9, 0, time.UTC)}}.options(t)
	der, err := Sign([]byte("x"), o)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBytes(der, nil, true); err != nil {
		t.Fatal(err)
	}
}

// TestSignDeterminism: RSA PKCS#1 v1.5 and Ed25519 are deterministic, so the
// bytes are; ECDSA and PSS draw randomness, so the bytes differ and both still
// verify. A signature that depended on anything else (map order, the clock)
// would show here.
func TestSignDeterminism(t *testing.T) {
	for _, c := range signCases() {
		if c.opts.Hash != crypto.SHA256 && c.key != "ed25519" || !c.opts.Detached {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			o := c.options(t)
			a, err := Sign([]byte("det"), o)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Sign([]byte("det"), o)
			if err != nil {
				t.Fatal(err)
			}
			randomised := c.key == "ec" || o.PSS
			if randomised == bytes.Equal(a, b) {
				t.Fatalf("equal=%v for a randomised=%v algorithm", bytes.Equal(a, b), randomised)
			}
			if verifyBytes(b, []byte("det"), false) != nil {
				t.Fatal("second signature does not verify")
			}
		})
	}
}

// TestSignLengths drives DER's three length forms through the container: the
// content (and so eContent and the digest's neighbours) at 0, 127, 128, 255,
// 256 and 70000 bytes.
func TestSignLengths(t *testing.T) {
	for _, n := range []int{0, 127, 128, 255, 256, 70000} {
		content := bytes.Repeat([]byte{0xAB}, n)
		for _, detached := range []bool{true, false} {
			o := signCase{"x", "ed25519", SignOptions{Detached: detached}}.options(t)
			der, err := Sign(content, o)
			if err != nil {
				t.Fatal(err)
			}
			if detached {
				// An empty detached content is a non-nil empty slice, not
				// "absent": Verify's nil means "none supplied".
				err = verifyBytes(der, append([]byte{}, content...), false)
			} else {
				err = verifyBytes(der, nil, true)
			}
			if err != nil {
				t.Fatalf("%d bytes, detached=%v: %v", n, detached, err)
			}
		}
	}
}

// TestSignChain: the chain is embedded, deduplicated, and the SET OF sorted.
func TestSignChain(t *testing.T) {
	ids := identities(t)
	o := signCase{"x", "rsa", SignOptions{}}.options(t)
	o.Chain = []*x509.Certificate{ids["ec"].cert, o.Certificate, ids["ed25519"].cert, ids["ec"].cert}
	der, err := Sign([]byte("x"), o)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(sd.Certificates) != 3 {
		t.Fatalf("%d certificates, want 3 distinct", len(sd.Certificates))
	}
	for i := 1; i < len(sd.Certificates); i++ {
		if bytes.Compare(sd.Certificates[i-1].Raw, sd.Certificates[i].Raw) >= 0 {
			t.Fatal("certificate SET OF is not in DER order")
		}
	}
	if _, err := sd.Verify(nil); err != nil {
		t.Fatal(err)
	}
}

// TestSignOtherContentType: a content type other than id-data forces
// version 3 and the attributes, and Verify reads it back.
func TestSignOtherContentType(t *testing.T) {
	tstInfo := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	o := signCase{"x", "ec", SignOptions{ContentType: tstInfo}}.options(t)
	der, err := Sign([]byte("x"), o)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Version != 3 || !sd.ContentType.Equal(tstInfo) {
		t.Fatalf("version %d type %v", sd.Version, sd.ContentType)
	}
	if _, err := sd.Verify(nil); err != nil {
		t.Fatal(err)
	}
	t.Run("openssl", func(t *testing.T) {
		if err := opensslVerify(openssl(t), t.TempDir(), der, nil, true); err != nil {
			t.Fatal(err)
		}
	})
}

// TestUEFIProfile pins what go-filesystems/uefi's private encoder writes — a
// PKCS#7 SignedData that is detached, signs the content itself with RSA
// PKCS#1 v1.5 over SHA-256, carries no signed attributes and embeds the one
// certificate — so that it can switch to Sign. The signature must be the
// plain RSA signature of SHA-256(content), which is what edk2's Pkcs7Verify
// recomputes, and OpenSSL's PKCS#7 reader (the one edk2 is built on) must
// accept the container.
func TestUEFIProfile(t *testing.T) {
	id := identities(t)["rsa"]
	content := []byte("UEFI time-based authenticated variable payload")
	der, err := Sign(content, SignOptions{
		Signer: id.key, Certificate: id.cert, Hash: crypto.SHA256, Detached: true, NoSignedAttrs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	s := sd.Signers[0]
	if sd.Version != 1 || s.Version != 1 || sd.Content != nil || s.SignedAttrs != nil || len(sd.Signers) != 1 ||
		len(sd.Certificates) != 1 || !s.SignatureAlgorithm.Algorithm.Equal(oidRSAEncryption) ||
		!s.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Fatalf("not the UEFI shape: %+v", sd)
	}
	sum := crypto.SHA256.New()
	sum.Write(content)
	if err := rsa.VerifyPKCS1v15(id.key.Public().(*rsa.PublicKey), crypto.SHA256, sum.Sum(nil), s.Signature); err != nil {
		t.Fatalf("the signature is not RSA PKCS#1 v1.5 over SHA-256(content): %v", err)
	}

	t.Run("openssl-pkcs7", func(t *testing.T) {
		ossl := openssl(t)
		dir := t.TempDir()
		sig, ctn := filepath.Join(dir, "sig.der"), filepath.Join(dir, "content")
		if err := os.WriteFile(sig, der, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ctn, content, 0o644); err != nil {
			t.Fatal(err)
		}
		// smime -verify drives the PKCS#7 API, not the CMS one.
		if out, err := exec.Command(ossl, "smime", "-verify", "-noverify", "-binary", "-inform", "DER",
			"-in", sig, "-content", ctn, "-out", filepath.Join(dir, "out")).CombinedOutput(); err != nil {
			t.Fatalf("openssl smime -verify: %v\n%s", err, out)
		}
	})
}

// failingSigner is a crypto.Signer that only wraps another, hiding its
// concrete type as a smart card or an HSM would.
type wrappedSigner struct{ crypto.Signer }

// TestSignWithOpaqueSigner: only crypto.Signer is used, so a key that is not
// a Go key type works, and a signer that fails surfaces its error.
func TestSignWithOpaqueSigner(t *testing.T) {
	for _, key := range []string{"rsa", "ec", "ed25519"} {
		o := signCase{"x", key, SignOptions{}}.options(t)
		o.Signer = wrappedSigner{o.Signer}
		der, err := Sign([]byte("x"), o)
		if err != nil {
			t.Fatal(key, err)
		}
		if err := verifyBytes(der, nil, true); err != nil {
			t.Fatal(key, err)
		}
	}
	o := signCase{"x", "rsa", SignOptions{}}.options(t)
	o.Signer = failing{o.Signer}
	if _, err := Sign([]byte("x"), o); err == nil || err.Error() != "cms: signing: card removed" {
		t.Fatalf("got %v", err)
	}
}

type failing struct{ crypto.Signer }

func (failing) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("card removed")
}

// fakePub is a public key type this package does not implement.
type fakePub struct{}

func (fakePub) Equal(crypto.PublicKey) bool { return true }

type fakeSigner struct{}

func (fakeSigner) Public() crypto.PublicKey { return fakePub{} }
func (fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// TestSignRefusals: each request Sign must not carry out, with the error
// class a caller branches on and a word of the reason.
func TestSignRefusals(t *testing.T) {
	ids := identities(t)
	rsaID, ecID := ids["rsa"], ids["ec"]
	base := func(mod func(*SignOptions)) SignOptions {
		o := SignOptions{Signer: rsaID.key, Certificate: rsaID.cert}
		mod(&o)
		return o
	}
	deadline := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		o    SignOptions
		is   error
		word string
	}{
		{"no signer", base(func(o *SignOptions) { o.Signer = nil }), ErrOptions, "both required"},
		{"no certificate", base(func(o *SignOptions) { o.Certificate = nil }), ErrOptions, "both required"},
		{"certificate not parsed", base(func(o *SignOptions) { o.Certificate = &x509.Certificate{} }), ErrOptions, "not a parsed one"},
		{"certificate without serial", base(func(o *SignOptions) {
			c := *rsaID.cert
			c.SerialNumber = nil
			o.Certificate = &c
		}), ErrOptions, "not a parsed one"},
		{"nil chain entry", base(func(o *SignOptions) { o.Chain = []*x509.Certificate{nil} }), ErrOptions, "chain certificate 0"},
		{"empty chain entry", base(func(o *SignOptions) { o.Chain = []*x509.Certificate{ecID.cert, {}} }), ErrOptions, "chain certificate 1"},
		{"certificate of another key", base(func(o *SignOptions) { o.Certificate = ecID.cert }), ErrOptions, "not the signer's"},
		{"SHA-1", base(func(o *SignOptions) { o.Hash = crypto.SHA1 }), ErrUnsupported, "collisions"},
		{"SHA-224", base(func(o *SignOptions) { o.Hash = crypto.SHA224 }), ErrUnsupported, "hash function"},
		{"MD5", base(func(o *SignOptions) { o.Hash = crypto.MD5 }), ErrUnsupported, "hash function"},
		{"Ed25519 with SHA-256", SignOptions{Signer: ids["ed25519"].key, Certificate: ids["ed25519"].cert, Hash: crypto.SHA256}, ErrOptions, "SHA-512"},
		{"Ed25519 without attributes", SignOptions{Signer: ids["ed25519"].key, Certificate: ids["ed25519"].cert, NoSignedAttrs: true, Detached: true}, ErrOptions, "only signed with signed attributes"},
		{"PSS with ECDSA", SignOptions{Signer: ecID.key, Certificate: ecID.cert, PSS: true}, ErrOptions, "needs an RSA key"},
		{"PSS with Ed25519", SignOptions{Signer: ids["ed25519"].key, Certificate: ids["ed25519"].cert, PSS: true}, ErrOptions, "needs an RSA key"},
		{"id-data-less attributes", base(func(o *SignOptions) {
			o.NoSignedAttrs, o.ContentType = true, asn1.ObjectIdentifier{1, 2, 3}
		}), ErrOptions, "needs signed attributes"},
		{"signing-time without attributes", base(func(o *SignOptions) {
			o.NoSignedAttrs, o.SigningTime = true, time.Now()
		}), ErrOptions, "none were asked for"},
		{"signing-certificate-v2 without attributes", base(func(o *SignOptions) {
			o.NoSignedAttrs, o.SigningCertificateV2 = true, true
		}), ErrOptions, "none were asked for"},
		{"invalid content type", base(func(o *SignOptions) { o.ContentType = asn1.ObjectIdentifier{1} }), ErrOptions, "content type"},
		{"year 10000", base(func(o *SignOptions) { o.SigningTime = deadline }), ErrOptions, "year 10000"},
		{"year -1", base(func(o *SignOptions) { o.SigningTime = time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC) }), ErrOptions, "year -1"},
		{"unknown key type", SignOptions{Signer: fakeSigner{}, Certificate: &x509.Certificate{
			Raw: []byte{1}, SerialNumber: big.NewInt(1), PublicKey: fakePub{}}}, ErrUnsupported, "fakePub"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// A refusal that is missing must show as a failed assertion, not
			// as a crash further in: turn a panic into a verdict.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Sign panicked instead of refusing: %v", r)
				}
			}()
			der, err := Sign([]byte("x"), c.o)
			if err == nil {
				t.Fatalf("signed: %x", der)
			}
			if !errors.Is(err, c.is) {
				t.Fatalf("%v is not %v", err, c.is)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(c.word)) {
				t.Fatalf("%q does not say %q", err, c.word)
			}
		})
	}
}

// TestSigningTimeBoundaries: the first and last years the time check lets
// through.
func TestSigningTimeBoundaries(t *testing.T) {
	for _, y := range []int{0, 9999} {
		o := signCase{"x", "ec", SignOptions{SigningTime: time.Date(y, 6, 1, 0, 0, 0, 0, time.UTC)}}.options(t)
		if _, err := Sign([]byte("x"), o); err != nil {
			t.Fatalf("year %d: %v", y, err)
		}
	}
}
