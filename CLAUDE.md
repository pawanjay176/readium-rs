# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

readium-rs is a Rust implementation for handling LCP (Licensed Content Protection) DRM for EPUB publications. The project provides functionality to:
- Parse and validate LCP license files (.lcpl)
- Download and process encrypted EPUB files
- Decrypt content using user passphrases
- Verify license integrity with cryptographic signatures

## Build Commands

```bash
# Build the project
cargo build

# Build with release optimizations
cargo build --release

# Run the CLI tool (requires --input argument)
cargo run -- --input path/to/license.lcpl

# Run all tests
cargo test

# Run a specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture

# Run tests in a specific module
cargo test license::tests
```

## Architecture

### Module Structure

The codebase is organized into focused modules:

- **license** (`src/license.rs`): Core LCP license document parsing and validation
  - Deserializes JSON license files with encryption metadata, user rights, and signatures
  - Implements canonical JSON serialization for signature verification (license:168-184)
  - Contains key_check method for validating user passphrases (license:198-216)

- **epub** (`src/epub.rs`): EPUB archive handling
  - Manages ZIP archive reading for .epub files
  - Extracts metadata files: `META-INF/container.xml`, `META-INF/encryption.xml`, `META-INF/license.lcpl`
  - Defines EPUB-specific content types (XHTML, HTML, NCX)

- **key** (`src/key.rs`): Cryptographic key derivation
  - `UserPassphrase`: Zeroized wrapper for user input
  - `UserEncryptionKey`: Derives 256-bit keys from passphrases using SHA-256
  - Uses zeroize to clear sensitive data from memory on drop

- **cipher** (`src/cipher.rs`): AES-256-CBC encryption/decryption
  - PKCS7 padding for block alignment
  - Provides `encrypt_aes_256_cbc` and `decrypt_aes_256_cbc` functions
  - Handles variable-length plaintext with automatic padding calculation

- **encoding** (`src/encoding.rs`): Serde custom formatters
  - `date_format`: RFC3339 datetime serialization/deserialization
  - `optional_date_format`: Same as above but for Option<DateTime>
  - `certificate_format`: Base64-encoded DER X.509 certificate handling

### Key Data Flow

1. **License Loading**: Read .lcpl JSON file → deserialize into `License` struct with encryption parameters
2. **EPUB Download**: Extract publication link from license → download encrypted .epub file
3. **Passphrase Verification**: User provides passphrase → hash with SHA-256 → decrypt key_check field → compare with license ID
4. **Content Decryption**: Use verified user key → decrypt content key → decrypt EPUB resources

### Cryptographic Operations

The LCP spec requires specific algorithms:
- **User Key Derivation**: SHA-256 hash of user passphrase
- **Content Encryption**: AES-256-CBC with PKCS7 padding
- **Signature Verification**: RSA-SHA256 (algorithm specified in license signature field)

The `key_check` field in the license contains an encrypted version of the license ID. Successful decryption with the user-derived key proves the user has the correct passphrase.

## Edition Note

The project uses `edition = "2024"` in Cargo.toml (line 4), which is non-standard. Ensure your Rust toolchain supports this or update to `edition = "2021"` if compilation fails.

## Security Considerations

This codebase handles sensitive cryptographic material:
- User passphrases are wrapped in zeroized types that clear memory on drop
- The cipher module implements constant-time operations where possible
- License signatures use X.509 certificates for provider verification

When modifying cryptographic code:
- Preserve zeroize attributes on sensitive types
- Do not log or print key material
- Use constant-time comparison for authentication checks
- Follow the LCP specification encryption profile requirements
