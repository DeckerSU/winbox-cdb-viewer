fn main() {
    println!("cargo:rerun-if-changed=assets/icon.png");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || std::env::var_os("CARGO_FEATURE_GUI").is_none()
    {
        return;
    }
    let icon = image::open("assets/icon.png")
        .expect("application icon must be valid PNG")
        .resize(256, 256, image::imageops::FilterType::Lanczos3);
    let path = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("icon.ico");
    icon.save_with_format(&path, image::ImageFormat::Ico)
        .expect("failed to create Windows icon");
    winresource::WindowsResource::new()
        .set_icon(path.to_str().expect("icon path must be Unicode"))
        .set("FileDescription", "WinBox CDB Viewer")
        .set("ProductName", "WinBox CDB Viewer")
        .compile()
        .expect("failed to compile Windows application resources");
}
