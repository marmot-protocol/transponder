# Changelog

## Unreleased

### Security

- Store the server secp256k1 secret key in zeroizing memory and erase temporary `SecretKey` values used during token decryption, addressing the long-term key retention risk reported in marmot-security#24 ([#36](https://github.com/marmot-protocol/transponder/pull/36)).
