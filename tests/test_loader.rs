use sbpf_analyzer::loader;
use std::path::Path;

#[test]
fn test_load_invalid_path_returns_error() {
    let result = loader::load_and_analyze(Path::new("/nonexistent/file.so"));
    assert!(result.is_err());
}

#[test]
fn test_load_invalid_elf_returns_error() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"not an elf file").unwrap();
    let result = loader::load_and_analyze(tmp.path());
    assert!(result.is_err());
}
