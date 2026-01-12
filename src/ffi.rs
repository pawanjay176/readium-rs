//! C FFI interface for LCP decryption library
//!
//! This module provides C-compatible functions for use from Lua/LuaJIT via FFI.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::cell::RefCell;

use crate::epub::{Epub, LICENSE_FILE, ENCRYPTION_FILE};

// Thread-local storage for the last error message
thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = RefCell::new(None);
}

fn set_error(msg: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = CString::new(msg).ok();
    });
}

fn clear_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

/// Check if an EPUB file is LCP encrypted.
///
/// # Arguments
/// * `epub_path` - Path to the EPUB file (null-terminated C string)
///
/// # Returns
/// * `1` if the file is LCP encrypted
/// * `0` if the file is not LCP encrypted
/// * `-1` on error (call lcp_get_error for details)
#[no_mangle]
pub extern "C" fn lcp_is_encrypted(epub_path: *const c_char) -> i32 {
    clear_error();

    let path = match unsafe { CStr::from_ptr(epub_path) }.to_str() {
        Ok(s) => PathBuf::from(s),
        Err(e) => {
            set_error(format!("Invalid UTF-8 in path: {}", e));
            return -1;
        }
    };

    match Epub::new(path) {
        Ok(epub) => {
            if epub.license().is_some() {
                1
            } else {
                0
            }
        }
        Err(e) => {
            // If we can't open the file, it's not a valid encrypted EPUB
            set_error(format!("Failed to open EPUB: {}", e));
            -1
        }
    }
}

/// Decrypt an LCP-encrypted EPUB to a new file.
///
/// # Arguments
/// * `epub_path` - Path to the encrypted EPUB file (null-terminated C string)
/// * `output_path` - Path where the decrypted EPUB will be written (null-terminated C string)
/// * `passphrase` - The user's passphrase (null-terminated C string)
///
/// # Returns
/// * `0` on success
/// * `1` if the passphrase is incorrect
/// * `2` if the file is not LCP encrypted
/// * `-1` on other errors (call lcp_get_error for details)
#[no_mangle]
pub extern "C" fn lcp_decrypt_epub(
    epub_path: *const c_char,
    output_path: *const c_char,
    passphrase: *const c_char,
) -> i32 {
    clear_error();

    // Parse input paths
    let input_path = match unsafe { CStr::from_ptr(epub_path) }.to_str() {
        Ok(s) => PathBuf::from(s),
        Err(e) => {
            set_error(format!("Invalid UTF-8 in input path: {}", e));
            return -1;
        }
    };

    let output = match unsafe { CStr::from_ptr(output_path) }.to_str() {
        Ok(s) => PathBuf::from(s),
        Err(e) => {
            set_error(format!("Invalid UTF-8 in output path: {}", e));
            return -1;
        }
    };

    let pass = match unsafe { CStr::from_ptr(passphrase) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("Invalid UTF-8 in passphrase: {}", e));
            return -1;
        }
    };

    // Open the EPUB
    let mut epub = match Epub::new(input_path.clone()) {
        Ok(e) => e,
        Err(e) => {
            set_error(format!("Failed to open EPUB: {}", e));
            return -1;
        }
    };

    // Check if it's LCP encrypted
    let license = match epub.license() {
        Some(l) => l,
        None => {
            set_error("EPUB is not LCP encrypted".to_string());
            return 2;
        }
    };

    // Verify passphrase and get user key
    let (user_key, _iv) = match license.key_check(pass) {
        Ok(keys) => keys,
        Err(_) => {
            set_error("Incorrect passphrase".to_string());
            return 1;
        }
    };

    // Decrypt the content key
    let content_key = match license.decrypt_content_key(&user_key) {
        Ok(k) => k,
        Err(e) => {
            set_error(format!("Failed to decrypt content key: {}", e));
            return -1;
        }
    };

    // Write decrypted EPUB
    match write_decrypted_epub(&input_path, &output, &content_key, &mut epub) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Get the last error message.
///
/// # Returns
/// A pointer to a null-terminated error string, or NULL if no error occurred.
/// The string is valid until the next call to any lcp_* function.
#[no_mangle]
pub extern "C" fn lcp_get_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        match e.borrow().as_ref() {
            Some(cstr) => cstr.as_ptr(),
            None => std::ptr::null(),
        }
    })
}

/// Write a decrypted EPUB file.
fn write_decrypted_epub(
    input_path: &PathBuf,
    output_path: &PathBuf,
    content_key: &[u8; 32],
    epub: &mut Epub,
) -> Result<(), String> {
    use crate::cipher::aes_cbc256::decrypt_aes_256_cbc;
    use flate2::read::DeflateDecoder;
    use std::fs::File;
    use std::io::{Read, Write};
    use zip::write::SimpleFileOptions;
    use zip::{ZipArchive, ZipWriter};

    // Open the input EPUB as a zip archive
    let input_file = File::open(input_path)
        .map_err(|e| format!("Failed to open input file: {}", e))?;
    let mut input_archive = ZipArchive::new(input_file)
        .map_err(|e| format!("Failed to read input archive: {}", e))?;

    // Create the output file
    let output_file = File::create(output_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;
    let mut output_archive = ZipWriter::new(output_file);

    // Parse encryption.xml to find encrypted files
    let encryption_xml = epub.encryption_xml();
    let encrypted_files = parse_encrypted_files(encryption_xml)?;

    // Copy/decrypt all files
    for i in 0..input_archive.len() {
        let mut file = input_archive.by_index(i)
            .map_err(|e| format!("Failed to read archive entry: {}", e))?;

        let name = file.name().to_string();

        // Skip LCP-specific files in output
        if name == LICENSE_FILE || name == ENCRYPTION_FILE {
            continue;
        }

        // Read file content
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|e| format!("Failed to read {}: {}", name, e))?;

        // Check if this file needs decryption
        let final_content = if let Some(compression) = encrypted_files.get(&name) {
            // This file is encrypted
            if content.len() < 16 {
                return Err(format!("File {} is too small to contain IV", name));
            }

            // Extract IV from first 16 bytes
            let iv: [u8; 16] = content[0..16]
                .try_into()
                .map_err(|_| format!("Invalid IV for {}", name))?;

            // Decrypt
            let decrypted = decrypt_aes_256_cbc(&content[16..], content_key, &iv)
                .map_err(|e| format!("Failed to decrypt {}: {}", name, e))?;

            // Decompress if needed
            if *compression == 8 {
                let mut decoder = DeflateDecoder::new(&decrypted[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)
                    .map_err(|e| format!("Failed to decompress {}: {}", name, e))?;
                decompressed
            } else {
                decrypted
            }
        } else {
            // Not encrypted, use as-is
            content
        };

        // Write to output archive
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        output_archive.start_file(&name, options)
            .map_err(|e| format!("Failed to start writing {}: {}", name, e))?;
        output_archive.write_all(&final_content)
            .map_err(|e| format!("Failed to write {}: {}", name, e))?;
    }

    output_archive.finish()
        .map_err(|e| format!("Failed to finalize output archive: {}", e))?;

    Ok(())
}

/// Parse encryption.xml to get a map of encrypted file paths to their compression method.
fn parse_encrypted_files(encryption_xml: Option<&str>) -> Result<std::collections::HashMap<String, u8>, String> {
    use std::collections::HashMap;

    let mut result = HashMap::new();

    let Some(xml_str) = encryption_xml else {
        return Ok(result);
    };

    let doc = roxmltree::Document::parse(xml_str)
        .map_err(|e| format!("Failed to parse encryption.xml: {}", e))?;

    for node in doc.descendants() {
        if node.tag_name().name() != "EncryptedData" {
            continue;
        }

        // Get the URI of the encrypted file
        let uri = node
            .descendants()
            .find(|n| n.tag_name().name() == "CipherReference")
            .and_then(|n| n.attribute("URI"));

        let Some(uri) = uri else {
            continue;
        };

        // Get compression method (default to 0 = no compression)
        let compression: u8 = node
            .descendants()
            .find(|n| n.tag_name().name() == "Compression")
            .and_then(|n| n.attribute("Method"))
            .and_then(|m| m.parse().ok())
            .unwrap_or(0);

        result.insert(uri.to_string(), compression);
    }

    Ok(result)
}
