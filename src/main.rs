use clap::Parser;
use readium_rs::{epub, license::License};
use std::{fs::File, io::Write, path::PathBuf};

/// lcpencrypt encrypts a publication using the LCP DRM
#[derive(Parser, Debug)]
#[command(about = "Encrypts publications using the LCP DRM", long_about = None)]
pub struct Args {
    /// Path for license lcpl file
    #[arg(short, long)]
    pub input: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Parse license and write epub
    let lcpl_file = File::open(args.input)?;
    let license: License = serde_json::from_reader(&lcpl_file)?;
    let resp = reqwest::blocking::get(
        license
            .publication_link()
            .expect("license file must have publication link to download"),
    )?
    .bytes()?;
    let mut file = File::create(PathBuf::from(format!("{}.epub", &license.id)))?;
    file.write_all(&resp)?;
    let epub = epub::Epub::new(PathBuf::from(&license.id), license).unwrap();

    for file in epub.metadata() {
        dbg!(&file);
    }
    // println!("{:?}", &epub.encryption().unwrap());
    println!("{:?}", &epub.license());
    Ok(())
}
