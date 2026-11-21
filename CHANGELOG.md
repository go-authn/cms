# Changelog

## Unreleased

### Security

- `Verify` refuses an attribute-less signature whose signed content is itself a
  DER `SET OF Attribute` carrying both a content-type and a message-digest
  attribute. A signature made WITH signedAttrs covers their DER (RFC 5652
  §5.4); re-packed without the key as a SignedData without signedAttrs, whose
  content is those attributes, it verified and named the signer for content
  never signed as content (MEDIUM). OpenSSL's `CMS_SignerInfo_verify_content`
  and smallstep/pkcs7 have the same ambiguity and no guard.
