//! Optional command-line exporter for address books.
use std::{io::Write, path::PathBuf};
use winbox_cdb as cdb;
fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let input = PathBuf::from(
        args.next()
            .ok_or("Usage: cdb-dump INPUT [--format json|text] [-o FILE] [--password-file FILE]")?,
    );
    let (mut output, mut password_path, mut text) = (None, None, false);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-o") | Some("--output") => {
                output = Some(PathBuf::from(args.next().ok_or("missing output")?))
            }
            Some("--password-file") => {
                password_path = Some(PathBuf::from(args.next().ok_or("missing password file")?))
            }
            Some("--format") => {
                let value = args.next().ok_or("missing format")?;
                text = match value.to_str() {
                    Some("text") => true,
                    Some("json") => false,
                    _ => return Err("format must be json or text".into()),
                };
            }
            _ => return Err("unknown argument".into()),
        }
    }
    let data = cdb::read_cdb(&input)?;
    let password = password_path
        .as_deref()
        .map(cdb::read_password)
        .transpose()?;
    let doc = cdb::decode_cdb(&data, password.as_ref().map(|p| p.as_slice()))?;
    let out = if text {
        cdb::format_text(&doc)?
    } else {
        cdb::format_json(&doc)?
    };
    if let Some(path) = output {
        cdb::write_private(&path, &out)
    } else {
        std::io::stdout()
            .write_all(out.as_bytes())
            .map_err(|e| e.to_string())
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(2);
    }
}
