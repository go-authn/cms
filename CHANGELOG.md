# Changelog

## v0.2.2

### Security

- `Verify` refuses signed attributes that carry two signing-time attributes,
  or a signing-time attribute with no value or several (RFC 5652 §11.3:
  "MUST have a single attribute value" and the SignedAttributes "MUST NOT
  include multiple instances of the signing-time attribute"). content-type
  and message-digest already had this rule (§11.1, §11.2); signing-time had
  none, so a message with two signing times verified and a reader of
  `Signer.SignedAttrs` taking the first and one taking the last disagreed
  about when it was signed (LOW; the time is signed, so only the signer can
  produce it).

- `Verify` refuses an attribute-less signature whose signed content is itself a
  DER `SET OF Attribute` carrying both a content-type and a message-digest
  attribute. A signature made WITH signedAttrs covers their DER (RFC 5652
  §5.4); re-packed without the key as a SignedData without signedAttrs, whose
  content is those attributes, it verified and named the signer for content
  never signed as content (MEDIUM). OpenSSL's `CMS_SignerInfo_verify_content`
  and smallstep/pkcs7 have the same ambiguity and no guard.
