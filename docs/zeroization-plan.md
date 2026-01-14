# Zeroization Implementation Plan

**Status: COMPLETE**

## Overview

This document outlines the implementation of secure memory zeroization for sensitive cryptographic material and device tokens in Transponder using the `zeroize` crate.

## Motivation

Even though Transponder is stateless and doesn't persist tokens, sensitive data can remain in memory after use. This poses risks from:

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
- HKDF output key material
- Decrypted plaintext buffer

### Step 4: Zeroize Dispatcher Tokens

Wrap token strings in `Zeroizing<String>` within the push message queue.

### Step 5: Update Tests

Ensure existing tests pass with zeroization enabled.

## Verification

All verification steps completed successfully:

1. ✅ All 193 tests pass (`cargo test`)
2. ✅ No clippy warnings (`cargo clippy -- -D warnings`)
3. ✅ Code compiles in release mode (`cargo build --release`)

## Files Modified

- `Cargo.toml` - Added `zeroize` dependency
- `src/crypto/token.rs` - Added `ZeroizeOnDrop` to structs, wrapped local variables
- `src/push/dispatcher.rs` - Wrapped token strings in `Zeroizing<String>`

## Security Notes

- The `zeroize` crate uses memory barriers to prevent compiler optimization of zeroing operations
- `ZeroizeOnDrop` trait ensures automatic cleanup when values go out of scope
- `Zeroizing<T>` wrapper provides RAII-style automatic zeroization

## References

- [zeroize crate documentation](https://docs.rs/zeroize/)
- [RustCrypto zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)
