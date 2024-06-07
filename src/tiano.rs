use std::alloc::*;
use std::os::raw::c_void;
use std::ptr::null_mut;

use crate::*;

pub fn efi_dec(src: &[u8]) -> Result<Vec<u8>, usize> {
    let mut src = Vec::from(src);
    let mut dest: *mut c_void = null_mut();
    let mut dest_size: u32 = 0;
    unsafe {
        let ret = Extract(
            src.as_mut_ptr() as *mut c_void,
            src.len() as u32,
            &mut dest,
            &mut dest_size,
            1,
        );
        if ret == 0 {
            Ok(Vec::from_raw_parts(
                dest as *mut u8,
                dest_size as usize,
                dest_size as usize,
            ))
        } else {
            Err(ret as usize)
        }
    }
}

pub fn efi_enc(src: &[u8]) -> Result<Vec<u8>, usize> {
    let mut src = Vec::from(src);
    unsafe {
        let dest = alloc(Layout::from_size_align_unchecked(src.len(), 1)) as *mut u8;
        let mut dest_size: u32 = src.len() as u32;
        let ret = EfiCompress(
            src.as_mut_ptr() as *mut u8,
            src.len() as u32,
            dest,
            &mut dest_size,
        );
        if ret == 0 {
            Ok(Vec::from_raw_parts(dest, dest_size as usize, src.len()))
        } else {
            Err(ret as usize)
        }
    }
}

pub fn tiano_dec(src: &[u8]) -> Result<Vec<u8>, usize> {
    let mut src = Vec::from(src);
    // Do not use Extract() from Common\Decompress.c.
    // Because it uses global variable, and will fail when test tiano_dec and efi_dec at the same time
    //
    //let mut dest: *mut c_void = null_mut();
    //let mut dest_size: u32 = 0;
    //unsafe {
    //    let ret = Extract(
    //        src.as_mut_ptr() as *mut c_void,
    //        src.len() as u32,
    //        &mut dest,
    //        &mut dest_size,
    //        2,
    //    );
    //    if ret == 0 {
    //        Ok(Vec::from_raw_parts(
    //            dest as *mut u8,
    //            dest_size as usize,
    //            dest_size as usize,
    //        ))
    //    } else {
    //        Err(ret as usize)
    //    }
    //}

    let dec_size = src[4] as usize
        + ((src[5] as usize) << 8)
        + ((src[6] as usize) << 16)
        + ((src[7] as usize) << 24);
    let mut out_buf = vec![0u8; dec_size];
    unsafe {
        let scratch = alloc(Layout::new::<SCRATCH_DATA>()) as *mut c_void;
        let ret = TDecompress(
            src.as_mut_ptr() as *mut c_void,
            out_buf.as_mut_ptr() as *mut c_void,
            scratch,
            2,
        );
        if ret == 0 {
            Ok(out_buf)
        } else {
            Err(ret as usize)
        }
    }
}

pub fn tiano_enc(src: &[u8]) -> Result<Vec<u8>, usize> {
    let mut src = Vec::from(src);
    unsafe {
        let dest = alloc(Layout::from_size_align_unchecked(src.len(), 1)) as *mut u8;
        let mut dest_size: u32 = src.len() as u32;
        let ret = TianoCompress(
            src.as_mut_ptr() as *mut u8,
            src.len() as u32,
            dest,
            &mut dest_size,
        );
        if ret == 0 {
            Ok(Vec::from_raw_parts(dest, dest_size as usize, src.len()))
        } else {
            Err(ret as usize)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_efi() {
        let test_path = std::env::current_dir().unwrap().join("test");
        let test_reference_bin_name = "efi_compressed.bin";
        let test_reference_bin = test_path.join(test_reference_bin_name);

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }

        let test_src = crate::test::get_test_file();

        assert!(
            std::process::Command::new(test_path.join("TianoCompress.exe"))
                .arg("-e")
                .arg(test_src.path().as_os_str())
                .arg("-o")
                .arg(test_reference_bin.as_os_str())
                .arg("--uefi")
                .current_dir(test_path.as_os_str())
                .status()
                .unwrap()
                .success()
        );
        let compressed = efi_enc(test_src.slice()).unwrap();

        let reference_buf = std::fs::read(test_path.join(&test_reference_bin)).unwrap();
        assert_eq!(reference_buf.len(), compressed.len());
        assert!(reference_buf.eq(&compressed));

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }

        let decompressed = efi_dec(&compressed).unwrap();
        assert_eq!(test_src.slice().len(), decompressed.len());
        assert!(test_src.slice().eq(&decompressed));
    }

    #[test]
    fn test_tiano() {
        let test_path = std::env::current_dir().unwrap().join("test");
        let test_reference_bin_name = "tiano_compressed.bin";
        let test_reference_bin = test_path.join(test_reference_bin_name);

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }

        let test_src = crate::test::get_test_file();

        assert!(
            std::process::Command::new(test_path.join("TianoCompress.exe"))
                .arg("-e")
                .arg(test_src.path().as_os_str())
                .arg("-o")
                .arg(test_reference_bin.as_os_str())
                .current_dir(test_path.as_os_str())
                .status()
                .unwrap()
                .success()
        );
        let compressed = tiano_enc(test_src.slice()).unwrap();

        let reference_buf = std::fs::read(test_path.join(&test_reference_bin)).unwrap();
        assert_eq!(reference_buf.len(), compressed.len());
        assert!(reference_buf.eq(&compressed));

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }

        let decompressed = tiano_dec(&compressed).unwrap();
        assert_eq!(test_src.slice().len(), decompressed.len());
        assert!(test_src.slice().eq(&decompressed));
    }
}
