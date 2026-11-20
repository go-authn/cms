package cms

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// ⛔⛔ EVERY SIGNATURE UNDER testdata/ WAS MADE BY OPENSSL, NOT BY THIS
// PACKAGE. A fixture written by the code under test can only agree with it:
// a parser that misread a field the same way its encoder wrote it would pass
// on every file. So the judge is the domain's reference implementation —
// `openssl cms` — and this file is how its output is produced and re-checked.
//
// Private keys are generated in a temporary directory and DISCARDED: only
// the certificates, the signatures and the content are committed. A test key
// in a repository is still a key in a repository, and secret scanners are
// right to object to one.

// fixture is one signature OpenSSL is asked to make.
type fixture struct {
	name string
	key  string   // rsa, ec or ed25519
	args []string // extra `openssl cms -sign` arguments
}

var fixtures = []fixture{
	{"rsa-detached", "rsa", nil},
	{"rsa-attached", "rsa", []string{"-nodetach"}},
	{"rsa-noattr", "rsa", []string{"-noattr"}},
	{"rsa-keyid", "rsa", []string{"-keyid"}},
	{"rsa-sha384", "rsa", []string{"-md", "sha384"}},
	{"rsa-sha512", "rsa", []string{"-md", "sha512"}},
	{"rsa-pss", "rsa", []string{"-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_pss_saltlen:digest"}},
	{"ec-detached", "ec", nil},
	{"ec-noattr", "ec", []string{"-noattr"}},
	{"ec-sha384", "ec", []string{"-md", "sha384"}},
	{"ed25519-detached", "ed25519", nil},
}

// theContent is what every fixture signs. In a PDF signature it would be the
// concatenation of the file's /ByteRange.
const theContent = "The signed content: in a PDF signature, the file's /ByteRange.\n"

// openssl finds an OpenSSL with the cms command. macOS ships LibreSSL as
// /usr/bin/openssl, so a Homebrew OpenSSL is preferred when present.
func openssl(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	p, err := exec.LookPath("openssl")
	if err == nil && exec.Command(p, "cms", "-help").Run() == nil {
		return p
	}
	if os.Getenv("CMS_REQUIRE_OPENSSL") == "1" {
		t.Fatal("CMS_REQUIRE_OPENSSL=1 and no openssl with the cms command was found")
	}
	t.Skip("no openssl with the cms command; the committed fixtures are still checked")
	return ""
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// TestRegenerateFixtures rewrites testdata/ from OpenSSL. It runs only when
// asked (CMS_REGENERATE=1), because the committed files are the record: a
// fresh key every run would make every signature differ in every diff.
func TestRegenerateFixtures(t *testing.T) {
	if os.Getenv("CMS_REGENERATE") != "1" {
		t.Skip("set CMS_REGENERATE=1 to rewrite testdata/ from openssl")
	}
	ossl := openssl(t)
	keys := t.TempDir()
	genpkey := map[string][]string{
		"rsa":     {"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"},
		"ec":      {"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"},
		"ed25519": {"-algorithm", "ED25519"},
	}
	for k, opts := range genpkey {
		run(t, keys, ossl, append([]string{"genpkey", "-out", k + ".key"}, opts...)...)
		run(t, keys, ossl, "req", "-x509", "-new", "-key", k+".key", "-out", k+".crt",
			"-subj", "/CN=go-authn cms test "+k, "-days", "36500",
			"-addext", "subjectKeyIdentifier=hash")
		crt, err := os.ReadFile(filepath.Join(keys, k+".crt"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", k+".crt"), crt, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	content := filepath.Join(keys, "content")
	if err := os.WriteFile(content, []byte(theContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "content"), []byte(theContent), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		out, err := filepath.Abs(filepath.Join("testdata", f.name+".der"))
		if err != nil {
			t.Fatal(err)
		}
		args := []string{"cms", "-sign", "-binary", "-in", content,
			"-signer", f.key + ".crt", "-inkey", f.key + ".key",
			"-outform", "DER", "-out", out}
		run(t, keys, ossl, append(args, f.args...)...)
	}
}

// TestOpenSSLAgrees asks OpenSSL to verify every committed fixture AND every
// tampered variant, and requires its verdict to equal this package's. The
// tampered half is the point: a judge that only ever sees good signatures
// cannot tell a verifier from one that accepts everything.
//
// -noverify skips certificate CHAIN validation on OpenSSL's side, because
// these certificates are self-signed and this package does not judge chains
// either (§5.6): both sides are asked the same question, whether the
// signature holds.
func TestOpenSSLAgrees(t *testing.T) {
	ossl := openssl(t)
	dir := t.TempDir()
	for _, f := range fixtures {
		der, err := os.ReadFile(filepath.Join("testdata", f.name+".der"))
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range variants(der) {
			t.Run(f.name+"/"+v.name, func(t *testing.T) {
				sigPath := filepath.Join(dir, "sig.der")
				contentPath := filepath.Join(dir, "content")
				if err := os.WriteFile(sigPath, v.der, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(contentPath, v.content, 0o644); err != nil {
					t.Fatal(err)
				}
				args := []string{"cms", "-verify", "-noverify", "-binary", "-inform", "DER",
					"-in", sigPath, "-out", filepath.Join(dir, "out")}
				if !attached(f) {
					args = append(args, "-content", contentPath)
				}
				theirs := exec.Command(ossl, args...).Run() == nil

				ours := verifyBytes(v.der, v.content, attached(f)) == nil
				if ours != theirs {
					t.Fatalf("openssl says %v, this package says %v", theirs, ours)
				}
			})
		}
	}
}

func attached(f fixture) bool {
	for _, a := range f.args {
		if a == "-nodetach" {
			return true
		}
	}
	return false
}

// verifyBytes is Parse then Verify, supplying the content only when the
// signature is detached.
func verifyBytes(der, content []byte, isAttached bool) error {
	sd, err := Parse(der)
	if err != nil {
		return err
	}
	if isAttached {
		_, err = sd.Verify(nil)
	} else {
		_, err = sd.Verify(content)
	}
	return err
}

type variant struct {
	name    string
	der     []byte
	content []byte
}

// variants is the untouched fixture and the tamperings both judges must
// refuse: one changed byte of content, and one changed byte at the END of
// the DER, which in every fixture here falls inside the signature value.
//
// ⛔ AND, WHEN THE CONTENT IS ATTACHED, ONE CHANGED BYTE OF IT INSIDE THE DER.
// The "content-changed" variant alters the file handed to a DETACHED verify;
// an attached verify never reads that file, so for -nodetach both judges said
// "valid" and agreed about nothing. 33 agreements included that one, and it
// tested no tampering at all — the count was right and the coverage was not.
func variants(der []byte) []variant {
	good := []byte(theContent)
	content := append([]byte(nil), good...)
	content[0] ^= 1
	sig := append([]byte(nil), der...)
	sig[len(sig)-1] ^= 1
	vs := []variant{
		{"untouched", der, good},
		{"content-changed", der, content},
		{"signature-changed", sig, good},
	}
	if at := bytes.Index(der, good); at >= 0 {
		embedded := append([]byte(nil), der...)
		embedded[at] ^= 1
		vs = append(vs, variant{"embedded-content-changed", embedded, good})
	}
	return vs
}

// errorsIs is errors.Is, named for the tests that assert which of the three
// error classes a refusal belongs to.
var errorsIs = errors.Is
