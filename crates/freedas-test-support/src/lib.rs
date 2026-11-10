//! Shared test fixtures.

pub fn temp_project() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let root = dir.path().to_path_buf();
    (dir, root)
}
