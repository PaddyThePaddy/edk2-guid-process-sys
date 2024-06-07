#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod lzma;
pub use lzma::*;
pub mod tiano;
pub use tiano::*;
pub mod crc32;
pub use crc32::*;
pub mod bortli;
pub use bortli::*;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error {0}")]
    Io(#[from] std::io::Error),
    #[error("Error code {0}")]
    Usize(usize),
    #[error("Error code {0}")]
    I32(i32),
    #[error("Error code {0}")]
    EfiStatus(EFI_STATUS),
    #[error("Checksum failed")]
    ChecksumFailed,
    #[error("Unexpected end of buffer")]
    UnexpectedEndOfBuffer,
    #[error("Out of memory")]
    OutOfMemory,
    #[error("Invalid parameter")]
    InvalidParameter,
}

#[cfg(test)]
mod test {
    use std::{
        io::{Cursor, Write},
        path::{Path, PathBuf},
        sync::{Arc, Mutex, OnceLock, Weak},
    };

    use rand::random;
    const TEST_FILENAME: &str = "test.bin";
    const TEST_FILE_SIZE_MB: usize = 512;

    pub struct TestFile {
        file_path: PathBuf,
        buf: Vec<u8>,
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            std::fs::remove_file(&self.file_path).unwrap();
        }
    }

    impl TestFile {
        fn create() -> Self {
            let path = std::env::current_dir()
                .unwrap()
                .join("test")
                .join(TEST_FILENAME);
            let mut buf = Vec::with_capacity(TEST_FILE_SIZE_MB * 1024 * 1024);
            let mut writer = Cursor::new(&mut buf);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(&path)
                .unwrap();

            for _ in 0..TEST_FILE_SIZE_MB * 1024 {
                writer.write_all(&[random(); 1024]).unwrap();
            }
            file.write(&buf).unwrap();
            drop(file);
            Self {
                file_path: path,
                buf,
            }
        }

        pub fn path(&self) -> &Path {
            &self.file_path
        }

        pub fn slice(&self) -> &[u8] {
            &self.buf
        }
    }

    static LOCK: OnceLock<Mutex<Weak<TestFile>>> = OnceLock::new();
    pub fn get_test_file() -> Arc<TestFile> {
        let mut lock = LOCK.get_or_init(|| Mutex::new(Weak::new())).lock().unwrap();
        if lock.strong_count() == 0 {
            let new_file = Arc::new(TestFile::create());
            *lock = Arc::downgrade(&new_file);
            return new_file;
        } else {
            lock.upgrade().unwrap()
        }
    }
}
