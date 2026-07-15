#[cfg(target_os = "macos")]
use std::fs;
use std::fs::OpenOptions;
#[cfg(any(target_os = "macos", test))]
use std::io::Cursor;
#[cfg(target_os = "macos")]
use std::io::Read;
use std::io::Write;
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

#[cfg(any(target_os = "macos", test))]
use image::{GenericImageView, ImageFormat, ImageReader, Limits};
#[cfg(any(target_os = "macos", test))]
use sha2::{Digest, Sha256};

use crate::RunnerError;

pub(crate) const SANDBOX_INBOX: &str = "/workspace/sandbox-guard-inputs";
pub(crate) const INBOX_DIRECTORY: &str = "sandbox-guard-inputs";

#[cfg(any(target_os = "macos", test))]
const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
#[cfg(any(target_os = "macos", test))]
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
#[cfg(any(target_os = "macos", test))]
const MAX_DIMENSION: u32 = 16_384;
#[cfg(any(target_os = "macos", test))]
const MAX_PIXELS: u64 = 40_000_000;

#[cfg(target_os = "macos")]
const MACOS_CLIPBOARD_SCRIPT: &str = r#"
on run argv
    set outputPath to POSIX file (item 1 of argv)
    try
        set imageData to the clipboard as «class PNGf»
    on error
        return "NO_IMAGE"
    end try
    set outputFile to missing value
    try
        set outputFile to open for access outputPath with write permission
        set eof outputFile to 0
        write imageData to outputFile
        close access outputFile
        return "OK"
    on error errorMessage
        try
            if outputFile is not missing value then close access outputFile
        end try
        error errorMessage
    end try
end run
"#;

#[derive(Debug)]
pub(crate) struct ClipboardImage {
    pub(crate) filename: String,
    pub(crate) png: Vec<u8>,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) sha256: String,
}

impl ClipboardImage {
    pub(crate) fn sandbox_path(&self) -> String {
        format!("{SANDBOX_INBOX}/{}", self.filename)
    }

    pub(crate) fn attachment_reference(&self) -> String {
        format!("@{INBOX_DIRECTORY}/{} ", self.filename)
    }

    pub(crate) fn audit_entry(&self) -> String {
        format!(
            "{}\timage/png\t{}x{}\t{}\t{}",
            self.sandbox_path(),
            self.width,
            self.height,
            self.png.len(),
            self.sha256
        )
    }
}

pub(crate) fn read_clipboard_image() -> Result<ClipboardImage, RunnerError> {
    #[cfg(target_os = "macos")]
    {
        read_macos_clipboard_image()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(RunnerError::ClipboardUnavailable(
            "host clipboard image import is currently supported on macOS only".to_owned(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn read_macos_clipboard_image() -> Result<ClipboardImage, RunnerError> {
    let directory = tempfile::Builder::new()
        .prefix("sandbox-guard-clipboard-")
        .tempdir()
        .map_err(|error| clipboard_error(format!("create private clipboard temporary: {error}")))?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .map_err(|error| clipboard_error(format!("secure clipboard temporary: {error}")))?;
    let input = directory.path().join("clipboard.png");
    let output = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(MACOS_CLIPBOARD_SCRIPT)
        .arg("--")
        .arg(&input)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| clipboard_error(format!("read macOS clipboard: {error}")))?;
    let result = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !output.status.success() {
        return Err(clipboard_error(format!(
            "macOS clipboard reader failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    if result != "OK" {
        return Err(clipboard_error(
            "clipboard does not contain a supported image".to_owned(),
        ));
    }
    let bytes = read_private_clipboard_file(&input)?;
    sanitize_png(&bytes)
}

#[cfg(target_os = "macos")]
fn read_private_clipboard_file(path: &Path) -> Result<Vec<u8>, RunnerError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| clipboard_error(format!("open clipboard image: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| clipboard_error(format!("inspect clipboard image: {error}")))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_INPUT_BYTES
    {
        return Err(clipboard_error(format!(
            "clipboard image must be a regular file no larger than {} MiB",
            MAX_INPUT_BYTES / 1024 / 1024
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| clipboard_error(format!("read clipboard image: {error}")))?;
    Ok(bytes)
}

#[cfg(any(target_os = "macos", test))]
fn sanitize_png(input: &[u8]) -> Result<ClipboardImage, RunnerError> {
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(clipboard_error("clipboard image is too large".to_owned()));
    }
    let mut reader = ImageReader::with_format(Cursor::new(input), ImageFormat::Png);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_PIXELS * 4);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|error| clipboard_error(format!("decode clipboard PNG: {error}")))?;
    let (width, height) = image.dimensions();
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(clipboard_error(
            "clipboard image dimensions exceed the safe pixel limit".to_owned(),
        ));
    }
    let mut png = Vec::new();
    image
        .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .map_err(|error| clipboard_error(format!("re-encode clipboard PNG: {error}")))?;
    if png.len() > MAX_OUTPUT_BYTES {
        return Err(clipboard_error(
            "sanitized clipboard PNG exceeds 32 MiB".to_owned(),
        ));
    }
    let sha256 = hex::encode(Sha256::digest(&png));
    Ok(ClipboardImage {
        filename: format!("clipboard-{}.png", uuid::Uuid::new_v4()),
        png,
        width,
        height,
        sha256,
    })
}

pub(crate) fn write_private_image(
    directory: &Path,
    image: &ClipboardImage,
) -> Result<PathBuf, RunnerError> {
    let path = directory.join(&image.filename);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|error| clipboard_error(format!("create private clipboard image: {error}")))?;
    file.write_all(&image.png)
        .and_then(|()| file.sync_all())
        .map_err(|error| clipboard_error(format!("write private clipboard image: {error}")))?;
    Ok(path)
}

fn clipboard_error(message: String) -> RunnerError {
    RunnerError::ClipboardUnavailable(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, RgbaImage};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn clipboard_image_is_decoded_reencoded_hashed_and_written_privately() {
        let source =
            DynamicImage::ImageRgba8(RgbaImage::from_pixel(2, 3, image::Rgba([1, 2, 3, 255])));
        let mut encoded = Vec::new();
        source
            .write_to(&mut Cursor::new(&mut encoded), ImageFormat::Png)
            .unwrap();

        let image = sanitize_png(&encoded).unwrap();
        assert_eq!((image.width, image.height), (2, 3));
        assert_eq!(image.sha256.len(), 64);
        let directory = tempfile::tempdir().unwrap();
        let path = write_private_image(directory.path(), &image).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn invalid_or_oversized_clipboard_images_fail_closed() {
        assert!(sanitize_png(b"not a png").is_err());
        assert!(sanitize_png(&vec![0_u8; MAX_INPUT_BYTES as usize + 1]).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_clipboard_script_compiles_without_reading_the_clipboard() {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new("/usr/bin/osacompile")
            .arg("-o")
            .arg(directory.path().join("clipboard.scpt"))
            .arg("-e")
            .arg(MACOS_CLIPBOARD_SCRIPT)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires an image in the interactive user's macOS clipboard"]
    fn imports_the_current_macos_clipboard_image() {
        let image = read_clipboard_image().unwrap();
        assert!(image.width > 0);
        assert!(image.height > 0);
        assert!(image.png.starts_with(b"\x89PNG\r\n\x1a\n"));
    }
}
