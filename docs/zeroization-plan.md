# Zeroization Implementation Plan

**Status: COMPLETE for all named buffers under program control. Crate-internal
temporaries in the pinned RustCrypto crates cannot be erased — see
"Coverage and residual gaps" below for the precise boundary.**

## Overview

This document outlines the implementation of secure memory zeroization for sensitive cryptographic material and device tokens in Transponder using the `zeroize` crate.

## Motivation

Even though Transponder doesn't persist tokens, keys, payloads, or user data, sensitive data can remain in memory after use. This poses risks from:

- Memory dumps (crash dumps, debuggers)
- Swap/hibernation writes to disk
- Side-channel attacks (Spectre/Meltdown)
- Core dumps containing plaintext secrets

Zeroization ensures sensitive data is overwritten with zeros when no longer needed, preventing these attack vectors.

## Scope

### Priority 1: Cryptographic Keys (CRITICAL)

| Item | Location | Type |
|------|----------|------|
| ECDH shared secret | `crypto/token.rs` | Local variable |
| HKDF PRK | `crypto/token.rs` | Local variable |
| Derived encryption key | `crypto/token.rs` | Local variable |
| Decrypted plaintext | `crypto/token.rs` | Local variable |

### Priority 2: Device Tokens (HIGH)

| Item | Location | Type |
|------|----------|------|
| `TokenPayload::device_token` | `crypto/token.rs` | Struct field |
| `EncryptedToken::ciphertext` | `crypto/token.rs` | Struct field |
| Token strings in dispatcher | `push/dispatcher.rs` | Local/message |

### Priority 3: Intermediate Buffers (MEDIUM)

| Item | Location | Type |
|------|----------|------|
| Ciphertext buffer | `crypto/token.rs` | Local variable |
| Nonce arrays | `crypto/token.rs` | Local variable |
| Ephemeral pubkey bytes | `crypto/token.rs` | Local variable |

## Implementation

### Step 1: Add Dependency

Add `zeroize` crate to `Cargo.toml`:

```toml
zeroize = { version = "1.8", features = ["derive", "zeroize_derive"] }
```

### Step 2: Derive ZeroizeOnDrop for Structs

Apply `#[derive(Zeroize, ZeroizeOnDrop)]` to:

- `EncryptedToken`
- `TokenPayload`

### Step 3: Zeroize Local Variables

Use `Zeroizing<T>` wrapper for sensitive local variables in decryption:

- Shared secret bytes
- HKDF PRK (see "Coverage and residual gaps" — derived via a manual
  extract/expand so the PRK is a wipeable local buffer)
- HKDF output key material
- Decrypted plaintext buffer

### Step 4: Zeroize Dispatcher Tokens

Wrap token strings in `Zeroizing<String>` within the push message queue.

### Step 5: Update Tests

Ensure existing tests pass with zeroization enabled.

## Coverage and residual gaps

### HKDF PRK (Priority 1)

`decrypt` performs the HKDF-SHA256 extract and expand steps manually with
`hmac::Hmac<Sha256>` (RFC 5869; the derived key is exactly one hash block, so
`OKM = T(1) = HMAC-SHA256(PRK, info || 0x01)`). The PRK and the derived key
each live in a `Zeroizing<[u8; 32]>` wiped on drop, and the intermediate HMAC
output buffers are zeroized after being copied out.

The `hkdf` crate is no longer used on the decrypt path: `Hkdf::new` stores the
PRK (as PRK-keyed HMAC state) inside the returned value, and hkdf 0.12.4 drops
that value without erasure and exposes no zeroize support. The crate remains a
dev-dependency as the reference implementation for the test-vector encryption
side, which cross-checks the manual derivation.

### What the pinned crates cannot erase (residual, NOT covered)

Complete erasure of every key-derived byte is **not** achievable with the
pinned RustCrypto crates — `hmac` 0.12.1, `sha2` 0.10, and `hkdf` 0.12.4 have
no zeroize integration:

- The `Hmac<Sha256>` values used for extract and expand hold key-derived
  internal state (the ipad/opad block states; for extract, a digest state that
  has absorbed the ECDH shared secret). `finalize()` consumes them, but their
  memory is released without being wiped.
- The same applies to transient SHA-256 compression state on the stack.

These temporaries are scoped to a single `decrypt` call, but their remnants
after drop are not zeroed — the memory-dump/swap/core-dump protection this
plan provides covers all *named* buffers, not these crate-internal
temporaries. Upgrading to hmac/digest releases with zeroize integration would
close most of the remainder.

## Verification

All verification steps completed successfully:

1. ✅ All 193 tests pass (`cargo test`)
2. ✅ No clippy warnings (`cargo clippy -- -D warnings`)
3. ✅ Code compiles in release mode (`cargo build --release`)

## Files Modified

- `Cargo.toml` - Added `zeroize` dependency; later added `hmac` (manual HKDF
  extract/expand) and demoted `hkdf` to a dev-dependency
- `src/crypto/token.rs` - Added `ZeroizeOnDrop` to structs, wrapped local
  variables, derived the encryption key via manual HKDF so the PRK is a
  `Zeroizing` buffer
- `src/push/dispatcher.rs` - Wrapped token strings in `Zeroizing<String>`

## Security Notes

- The `zeroize` crate uses memory barriers to prevent compiler optimization of zeroing operations
- `ZeroizeOnDrop` trait ensures automatic cleanup when values go out of scope
- `Zeroizing<T>` wrapper provides RAII-style automatic zeroization

## References

- [zeroize crate documentation](https://docs.rs/zeroize/)
- [RustCrypto zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)
