use std::{fs::File, io::Read, path::PathBuf};
use zip::ZipArchive;

use crate::license::License;

/// Filenames for specific metadata files
pub const CONTAINER_FILE: &str = "META-INF/container.xml";
pub const ENCRYPTION_FILE: &str = "META-INF/encryption.xml";
pub const LICENSE_FILE: &str = "META-INF/license.lcpl";

/// Content types for files used within epubs.
pub const CONTENT_TYPE_XHTML: &str = "application/xhtml+xml";
pub const CONTENT_TYPE_HTML: &str = "text/html";
pub const CONTENT_TYPE_NCX: &str = "application/x-dtbncx+xml";
pub const CONTENT_TYPE_EPUB: &str = "application/epub+zip";


fn read_file_from_archive(
    archive: &mut ZipArchive<File>,
    filename: &str,
) -> Result<Option<String>, String> {
    let Ok(mut zipfile) = archive.by_path(filename) else {
        return Ok(None);
    };
    let mut target = Vec::with_capacity(zipfile.size() as usize);
    zipfile
        .read_to_end(&mut target)
        .map_err(|e| format!("Failed to read container.xml file, err: {}", e))?;
    String::from_utf8(target)
        .map(Some)
        .map_err(|e| format!("Invalid string data in container.xml, err: {}", e))
}


/// Given an ebpub file, unzip it and view list all internal resources
#[derive(Debug)]
pub struct Epub {
    archive: ZipArchive<File>,
    container: String,
    encryption: Option<String>,
    license: License,
}



impl Epub {
    pub fn new(path: PathBuf, license: License) -> Result<Self, String> {
        let epub_file = File::open(&path).map_err(|e| format!("Unable to open file {}", e))?;
        let mut zip = zip::ZipArchive::new(epub_file)
            .map_err(|e| format!("Unable to read epub archive {}", e))?;
        let container = read_file_from_archive(&mut zip, CONTAINER_FILE)?
            .ok_or_else(|| "metadata must container container.xml".to_string())?;
        let encryption = read_file_from_archive(&mut zip, ENCRYPTION_FILE)?;
        Ok(Self {
            archive: zip,
            container,
            encryption,
            license,
        })
    }

    pub fn license(&self) -> &License {
        &self.license
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
