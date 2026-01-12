use clap::Parser;
use readium_lcp::epub;
use std::path::PathBuf;

/// lcpencrypt encrypts a publication using the LCP DRM
#[derive(Parser, Debug)]
#[command(about = "Encrypts publications using the LCP DRM", long_about = None)]
pub struct Args {
    /// Path for encrypted epub
    #[arg(short, long)]
    pub input: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Open epub file
    let mut epub = epub::Epub::new(args.input).unwrap();

    // Try verifying passphrase by decrypting content key
    let user_key = {
        let license = epub.license().unwrap();
        license.key_check("test1234").unwrap().0
    };
    epub.decrypt_encrypted_content(&user_key).unwrap();

    Ok(())
}
