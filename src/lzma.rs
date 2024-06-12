use std::{
    alloc::{alloc, Layout},
    ptr::{addr_of, null_mut},
};

use crate::*;

extern "C" {
    static mut g_Alloc: ISzAlloc;
}

const LZMA_HEADER_SIZE: usize = (LZMA_PROPS_SIZE + 8) as usize;

pub fn lzma_dec(src: &[u8], f86: bool) -> Result<Vec<u8>, i32> {
    let mut dec_size = 0;
    for i in 0..8 {
        dec_size += (src[LZMA_PROPS_SIZE as usize + i] as usize) << (i * 8);
    }
    let mut dec_buf = vec![0u8; dec_size];
    let mut in_size = src.len() - LZMA_HEADER_SIZE;
    let mut status: ELzmaStatus = 0;
    unsafe {
        let ret = LzmaDecode(
            dec_buf.as_mut_ptr(),
            &mut dec_size,
            src[LZMA_HEADER_SIZE..].as_ptr(),
            &mut in_size,
            src[..LZMA_HEADER_SIZE].as_ptr(),
            LZMA_PROPS_SIZE,
            ELzmaFinishMode_LZMA_FINISH_END,
            &mut status,
            addr_of!(g_Alloc),
        );
        if f86 {
            x86_convert(dec_buf.as_mut_slice(), 0);
        }
        if ret == SZ_OK as i32 {
            Ok(dec_buf)
        } else {
            Err(ret)
        }
    }
}

fn x86_convert(buf: &mut [u8], encoding: i32) {
    let mut state: u32 = 0;
    unsafe {
        x86_Convert(buf.as_mut_ptr(), buf.len(), 0, &mut state, encoding);
    }
}

pub fn lzma_enc(src: &[u8], f86: bool) -> Result<Vec<u8>, i32> {
    let out_size = src.len() / 20 * 21 + (1 << 16);
    let mut src = Vec::from(src);
    unsafe {
        let prop = alloc(Layout::new::<CLzmaEncProps>()) as *mut CLzmaEncProps;
        let mut dest = vec![0u8; out_size];
        LzmaEncProps_Init(prop);
        LzmaEncProps_Normalize(prop);
        if f86 {
            x86_convert(&mut src, 1);
        }
        let mut out_size_processed = out_size - LZMA_HEADER_SIZE;
        let mut out_prop_size = LZMA_PROPS_SIZE as usize;
        for i in 0..8 {
            dest[i + LZMA_PROPS_SIZE as usize] = (src.len() >> (8 * i)) as u8;
        }
        let ret = LzmaEncode(
            dest[LZMA_HEADER_SIZE..].as_mut_ptr(),
            &mut out_size_processed as *mut usize,
            src.as_mut_ptr(),
            src.len(),
            prop,
            dest.as_mut_ptr(),
            &mut out_prop_size as *mut usize,
            0,
            null_mut(),
            addr_of!(g_Alloc),
            addr_of!(g_Alloc),
        );
        dest.truncate(out_size_processed + LZMA_HEADER_SIZE);
        if ret == SZ_OK as i32 {
            Ok(dest)
        } else {
            Err(ret)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    const TOOL_NAME: &str = "LzmaCompress.exe";
    #[cfg(not(target_os = "windows"))]
    const TOOL_NAME: &str = "LzmaCompress";

    #[test]
    fn test_lzma() {
        let test_path = std::env::current_dir().unwrap().join("test");
        let test_reference_bin_name = "lzma_compressed.bin";
        let test_reference_bin = test_path.join(test_reference_bin_name);

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }

        let test_src = crate::test::get_test_file();

        assert!(std::process::Command::new(test_path.join(TOOL_NAME))
            .arg("-e")
            .arg(test_src.path().as_os_str())
            .arg("-o")
            .arg(test_reference_bin.as_os_str())
            .current_dir(test_path.as_os_str())
            .status()
            .unwrap()
            .success());
        let compressed = lzma_enc(test_src.slice(), false).unwrap();

        let reference_buf = std::fs::read(test_path.join(&test_reference_bin)).unwrap();
        assert_eq!(reference_buf.len(), compressed.len());
        assert!(reference_buf.eq(&compressed));

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }

        let decompressed = lzma_dec(&compressed, false).unwrap();
        assert_eq!(test_src.slice().len(), decompressed.len());
        assert!(test_src.slice().eq(&decompressed));
    }

    #[test]
    fn test_lzma_f86() {
        let test_path = std::env::current_dir().unwrap().join("test");
        let test_reference_bin_name = "lzma_compressed_f86.bin";
        let test_reference_bin = test_path.join(test_reference_bin_name);

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }

        let test_src = crate::test::get_test_file();

        assert!(std::process::Command::new(test_path.join(TOOL_NAME))
            .arg("-e")
            .arg(test_src.path().as_os_str())
            .arg("-o")
            .arg(test_reference_bin.as_os_str())
            .arg("--f86")
            .current_dir(test_path.as_os_str())
            .status()
            .unwrap()
            .success());
        let compressed = lzma_enc(test_src.slice(), true).unwrap();

        let reference_buf = std::fs::read(test_path.join(&test_reference_bin)).unwrap();
        assert_eq!(reference_buf.len(), compressed.len());
        assert!(reference_buf.eq(&compressed));

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }

        let decompressed = lzma_dec(&compressed, true).unwrap();
        assert_eq!(test_src.slice().len(), decompressed.len());
        assert!(test_src.slice().eq(&decompressed));
    }
}
