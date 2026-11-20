# cms

Read and verify **CMS SignedData** ([RFC 5652](https://www.rfc-editor.org/rfc/rfc5652))
in pure Go, with no dependencies beyond the standard library — the container
behind a PDF signature, a UEFI authenticated variable and an S/MIME message.
`CGO_ENABLED=0`.

```go
sd, err := cms.Parse(der)          // the signature's DER, e.g. a PDF's /Contents
if err != nil { … }
certs, err := sd.Verify(signed)    // the bytes it signed; nil when attached
if err != nil { … }
// certs[i] is the certificate signer i used. Whether to TRUST it — its chain,
// validity and revocation — is yours: crypto/x509's Verify, and
// go-authn/revocation for CRLs.
```

## What it checks

Every rule below is enforced, and every refusal is tested **by message**, so a
test cannot pass because some other check happened to fire first.

| RFC 5652 | rule |
|---|---|
| §5.3 | both signer-identifier forms are read: issuer and serial, and subject key identifier |
| §5.3 | `signedAttrs` must be present when the content is not `id-data`, and is never an empty set |
| §5.3, §11.1 | exactly one `content-type` attribute, with exactly one value |
| §5.3, §11.2 | exactly one `message-digest` attribute, with exactly one value |
| §5.6 | the signed content type equals `eContentType` |
| §5.6 | the digest is **recomputed here** — "The recipient MUST NOT rely on any message digest values computed by the originator" |
| §5.4 | the signature covers `signedAttrs` with its `[0] IMPLICIT` tag rewritten to `SET OF`, on the bytes as they arrived — never a re-encoding |
| §5.1 | an unimplemented algorithm is refused gracefully, as `ErrUnsupported` |

Beyond the RFC, a signature algorithm that names a hash of its own
(`sha256WithRSAEncryption`, `ecdsa-with-SHA384`) must name the **same** hash
as the `digestAlgorithm`. Otherwise one SignerInfo would be making two
statements about which hash protects it, and only one would be checked.

**Algorithms:** RSA PKCS #1 v1.5, RSASSA-PSS, ECDSA and Ed25519 ([RFC 8419](https://www.rfc-editor.org/rfc/rfc8419)),
over SHA-256, SHA-384 and SHA-512. The signature arithmetic itself is
`crypto/x509`'s `CheckSignature`, not reimplemented here.

**Refused by name:** SHA-1 (collisions in it are practical), and RSASSA-PSS
parameters other than the ones `crypto/x509` verifies — the digest's hash,
MGF1 over that hash, and a hash-length salt.

## Three errors, because a caller needs three answers

| error | means |
|---|---|
| `ErrMalformed` | not a SignedData this package can read |
| `ErrUnsupported` | a signature, using something not implemented here |
| `ErrInvalid` | readable and supported, and the signature does not hold |

The fuzz targets hold this as an invariant: every refusal wraps **exactly one**
of the three. A decoder error passed up unclassified would leave a caller
unable to tell a forgery from a format it merely does not speak.

## ⛔ What it does not do — yet

- **DER only.** RFC 5652 allows the outer structure to be BER, and some
  producers write indefinite lengths. `encoding/asn1` does not read them, so
  such an input is **refused** as `ErrMalformed`, never guessed at. The signed
  attributes must be DER in every case (§5.3), so this limit never weakens what
  is verified — it only turns away some well-formed inputs.
- **No signing.** This release reads and verifies; producing a SignedData comes
  next. One unexported encoder already exists in the fleet, in
  `go-filesystems/uefi`, and is meant to move here rather than be written twice.
- **No chain validation**, on purpose: RFC 5652 §5.6 places it "beyond the
  scope of this document". `Verify` returns the certificates that signed; trust
  is a separate decision with separate inputs.
- **Every signer must verify.** §5.1 lets an application accept one good
  signature from a signer that signed several times; a caller that wants that
  can verify signers individually.

## How it is judged

The judge is **OpenSSL's `cms` command**, not this package: a fixture written
by the code under test can only agree with it.

- **Eleven signatures made by OpenSSL 4.1.0** are committed under `testdata/`:
  RSA (attached, detached, without attributes, by key identifier, SHA-384,
  SHA-512), RSASSA-PSS, ECDSA P-256 (with and without attributes, SHA-384) and
  Ed25519. Private keys are generated in a temporary directory and discarded;
  only certificates, signatures and content are committed.
- **`TestOpenSSLAgrees`** hands each fixture, and each of its tampered variants,
  to `openssl cms -verify` and to this package, and requires the same verdict:
  **34 of 34 agree**, the tampered ones refused by both. The tampering includes
  a byte of the content *inside* an attached signature — the first version of
  this test checked only the detached form and so tested no tampering at all on
  the attached one.
- The rules OpenSSL will never produce a violation of — duplicate attributes,
  a lying content type, mismatched hashes — are built by changing OpenSSL's
  output in exactly one place. The builder first proves it is the identity: an
  unchanged rebuild must equal the fixture byte for byte.

⛔ **The oracle found a real defect before the first commit.** The parser read
the `[0] EXPLICIT` wrapper of `eContent` as if it were the OCTET STRING inside
it, so it could read **no attached signature at all**. Detached signatures —
the only kind a PDF uses — never reached that line, which is why everything
else passed.

## Measured

- **Coverage: every block** — 0 of 160 uncovered, judged by `covblocks`, which
  counts blocks rather than printing a rounded percentage.
- **Mutation-checked:** disabling the duplicate-attribute check turns its tests
  red, and the failure shows why messages are asserted — with the check gone,
  the forged input is *still* refused, by the RSA check, so a test asking only
  for "an error" would have stayed green.
- **Fuzzed:** `FuzzVerify` asserts that nothing verifies unless what its
  signature binds — signed attributes, signature, public key, content — is
  exactly what OpenSSL signed. 13 694 176 executions in 120 s at a 1-minute
  load of 3.5, no failure. Disabling the signature check makes it report a
  forgery in **5.7 s**; that input is in the committed corpus, so a bypass
  fails a plain `go test`.
- `go vet` on darwin, linux, windows, and the 32-bit `386` and `arm` targets.

## Install

```
go get github.com/go-authn/cms
```

## License

BSD 3-Clause.
