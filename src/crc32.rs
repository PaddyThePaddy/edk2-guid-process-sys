use crate::{CalculateCrc32, EFI_STATUS, EFI_SUCCESS};

#[allow(dead_code)]
fn edk2_get_crc32(buf: &[u8]) -> Result<u32, crate::Error> {
    let mut crc_out = 0u32;
    let mut src = Vec::from(buf);
    let data_size = buf.len() as u64;
    unsafe {
        let status = CalculateCrc32(src.as_mut_ptr(), data_size, &mut crc_out as *mut u32);
        if status != EFI_SUCCESS as EFI_STATUS {
            return Err(crate::Error::EfiStatus(status));
        }
    }
    Ok(crc_out)
}

#[cfg(not(feature = "crc32fast"))]
pub fn get_crc32(buf: &[u8]) -> Result<u32, crate::Error> {
    Ok(edk2_get_crc32(buf)?)
}

#[cfg(feature = "crc32fast")]
pub fn get_crc32(buf: &[u8]) -> Result<u32, crate::Error> {
    Ok(crc32fast::hash(buf))
}

pub fn crc32_enc(buf: &[u8]) -> Result<Vec<u8>, crate::Error> {
    let crc = get_crc32(buf)?;
    let mut section = Vec::with_capacity(buf.len() + 4);
    section.extend_from_slice(crc.to_le_bytes().as_slice());
    section.extend_from_slice(buf);
    Ok(section)
}

pub fn crc32_dec(buf: &[u8]) -> Result<Vec<u8>, crate::Error> {
    if buf.len() < 4 {
        return Err(crate::Error::UnexpectedEndOfBuffer);
    }
    let src_crc = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let calculated_crc = get_crc32(&buf[4..])?;
    if src_crc != calculated_crc {
        return Err(crate::Error::ChecksumFailed);
    }
    Ok(Vec::from(&buf[4..]))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_crc32() {
        let src_buf = std::fs::read("test/GenCrc32.exe").unwrap();
        assert_eq!(edk2_get_crc32(&src_buf).unwrap(), crc32fast::hash(&src_buf));
    }

    #[test]
    fn test_crc32() {
        let test_path = std::env::current_dir().unwrap().join("test");
        let test_reference_bin_name = "crc32.bin";
        let test_reference_bin = test_path.join(test_reference_bin_name);

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }

        let test_src = crate::test::get_test_file();

        assert!(std::process::Command::new(test_path.join("GenCrc32.exe"))
            .arg("-e")
            .arg(test_src.path().as_os_str())
            .arg("-o")
            .arg(test_reference_bin.as_os_str())
            .current_dir(test_path.as_os_str())
            .status()
            .unwrap()
            .success());
        let compressed = crc32_enc(test_src.slice()).unwrap();

        let reference_buf = std::fs::read(test_path.join(&test_reference_bin)).unwrap();
        assert_eq!(reference_buf.len(), compressed.len());
        assert!(reference_buf.eq(&compressed));

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }

        let decompressed = crc32_dec(&compressed).unwrap();
        assert_eq!(test_src.slice().len(), decompressed.len());
        assert!(test_src.slice().eq(&decompressed));
    }
}
