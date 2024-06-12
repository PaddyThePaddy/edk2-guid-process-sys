use std::{
    io::{BufRead, Cursor, Read, Seek, Write},
    ptr::null_mut,
};

use scopeguard::defer;

use crate::{
    kFileBufferSize, BrotliAllocFunc, BrotliDecoderCreateInstance, BrotliDecoderDecompressStream,
    BrotliDecoderDestroyInstance, BrotliDecoderParameter_BROTLI_DECODER_PARAM_LARGE_WINDOW,
    BrotliDecoderResult_BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT,
    BrotliDecoderResult_BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT,
    BrotliDecoderResult_BROTLI_DECODER_RESULT_SUCCESS, BrotliDecoderSetParameter,
    BrotliEncoderCompressStream, BrotliEncoderCreateInstance, BrotliEncoderDestroyInstance,
    BrotliEncoderHasMoreOutput, BrotliEncoderIsFinished,
    BrotliEncoderOperation_BROTLI_OPERATION_FINISH, BrotliEncoderOperation_BROTLI_OPERATION_FLUSH,
    BrotliEncoderParameter_BROTLI_PARAM_LGWIN, BrotliEncoderParameter_BROTLI_PARAM_QUALITY,
    BrotliEncoderParameter_BROTLI_PARAM_SIZE_HINT, BrotliEncoderSetParameter, BrotliFreeFunc,
    BROTLI_MAX_WINDOW_BITS, BROTLI_MIN_WINDOW_BITS, BROTLI_TRUE, BROTLI_WINDOW_GAP,
    DECODE_HEADER_SIZE, GAP_MEM_BLOCK,
};

const DEFAULT_QUALITY: u32 = 9;
const DEFAULT_LGWIN: u32 = 22;
const DEFAULT_GAP: i64 = 1;

fn BROTLI_MAX_BACKWARD_LIMIT(lg_win: u32) -> usize {
    (1 << lg_win as usize) - BROTLI_WINDOW_GAP as usize
}

/// Note: the produced compressed buffer is not exactly
/// the same with the one produced by EDK2 BrotliCompress.exe
/// But it can still be decompressed successfully
pub fn brotli_enc(buf: &[u8]) -> Result<Vec<u8>, crate::Error> {
    let mut out = brotli_enc_worker(buf, None)?;
    let mut scratch_buf_size = 0;
    brotli_dec_worker(&out, Some(&mut scratch_buf_size))?;

    let mut out_writer = Cursor::new(&mut out);
    out_writer.write_all((buf.len() as i64).to_le_bytes().as_slice())?;
    out_writer.write_all(
        (scratch_buf_size as i64 + DEFAULT_GAP * GAP_MEM_BLOCK as i64 + kFileBufferSize as i64 * 2)
            .to_le_bytes()
            .as_slice(),
    )?;
    Ok(out)
}

fn brotli_enc_worker(buf: &[u8], quality: Option<u32>) -> Result<Vec<u8>, crate::Error> {
    let mut next_in = vec![0u8; kFileBufferSize];
    let mut next_out = vec![0u8; kFileBufferSize];
    let mut out_buf = vec![];
    let mut out_writer = Cursor::new(&mut out_buf);
    let mut in_reader = Cursor::new(buf);
    out_writer.seek(std::io::SeekFrom::Start(DECODE_HEADER_SIZE as u64))?;

    unsafe {
        let state = BrotliEncoderCreateInstance(None, None, null_mut());
        defer!(BrotliEncoderDestroyInstance(state));
        if state.is_null() {
            return Err(crate::Error::OutOfMemory);
        }
        if BrotliEncoderSetParameter(
            state,
            BrotliEncoderParameter_BROTLI_PARAM_QUALITY,
            quality.unwrap_or(DEFAULT_QUALITY),
        ) != BROTLI_TRUE as i32
        {
            return Err(crate::Error::InvalidParameter);
        }

        let mut lg_win = DEFAULT_LGWIN;
        if !buf.is_empty() {
            lg_win = BROTLI_MIN_WINDOW_BITS;
            while BROTLI_MAX_BACKWARD_LIMIT(lg_win) < buf.len() {
                lg_win += 1;
                if lg_win == BROTLI_MAX_WINDOW_BITS {
                    break;
                }
            }
        }
        if BrotliEncoderSetParameter(state, BrotliEncoderParameter_BROTLI_PARAM_LGWIN, lg_win)
            != BROTLI_TRUE as i32
        {
            return Err(crate::Error::InvalidParameter);
        }

        if !buf.is_empty() {
            let size_hint = buf.len().min(1 << 30);

            if BrotliEncoderSetParameter(
                state,
                BrotliEncoderParameter_BROTLI_PARAM_SIZE_HINT,
                size_hint as u32,
            ) != BROTLI_TRUE as i32
            {
                return Err(crate::Error::InvalidParameter);
            }
        }

        let mut is_eof = false;
        let mut available_in = 0usize;
        let mut available_out = next_out.len();
        let mut total_out = 0usize;
        loop {
            if available_in == 0 && !is_eof {
                available_in = in_reader.read(&mut next_in)?;
                is_eof = is_reader_eof(&mut in_reader)?;
            }

            if !is_eof {
                loop {
                    let mut in_pointer = next_in.as_ptr();
                    let mut out_pointer = next_out.as_mut_ptr();
                    let status = BrotliEncoderCompressStream(
                        state,
                        BrotliEncoderOperation_BROTLI_OPERATION_FLUSH,
                        &mut available_in as *mut usize,
                        &mut in_pointer as *mut *const u8,
                        &mut available_out as *mut usize,
                        &mut out_pointer as *mut *mut u8,
                        &mut total_out as *mut usize,
                    );
                    if status == 0 {
                        return Err(crate::Error::I32(status));
                    }
                    let written = out_pointer as usize - next_out.as_ptr() as usize;
                    next_out.set_len(written);
                    out_writer.write_all(&next_out[..written])?;
                    next_out.clear();
                    available_out = kFileBufferSize;
                    if !(available_in > 0 || BrotliEncoderHasMoreOutput(state) != 0) {
                        break;
                    }
                }
            } else {
                loop {
                    let mut in_pointer = next_in.as_ptr();
                    let mut out_pointer = next_out.as_mut_ptr();
                    let status = BrotliEncoderCompressStream(
                        state,
                        BrotliEncoderOperation_BROTLI_OPERATION_FINISH,
                        &mut available_in as *mut usize,
                        &mut in_pointer as *mut *const u8,
                        &mut available_out as *mut usize,
                        &mut out_pointer as *mut *mut u8,
                        &mut total_out as *mut usize,
                    );
                    if status == 0 {
                        return Err(crate::Error::I32(status));
                    }
                    let written = out_pointer as usize - next_out.as_ptr() as usize;
                    next_out.set_len(written);
                    out_writer.write_all(&next_out[..written])?;
                    next_out.clear();
                    available_out = kFileBufferSize;
                    if !(available_in > 0 || BrotliEncoderHasMoreOutput(state) != 0) {
                        break;
                    }
                }
            }
            if BrotliEncoderIsFinished(state) != 0 {
                break;
            }
        }
    }
    Ok(out_buf)
}

pub fn brotli_dec(buf: &[u8]) -> Result<Vec<u8>, crate::Error> {
    brotli_dec_worker(buf, None)
}

fn brotli_dec_worker(
    buf: &[u8],
    ScratchBufferSize: Option<&mut usize>,
) -> Result<Vec<u8>, crate::Error> {
    let mut next_in = vec![0u8; kFileBufferSize];
    let mut next_out = vec![0u8; kFileBufferSize];
    let mut out_buf = vec![];
    let mut out_writer = Cursor::new(&mut out_buf);
    let mut in_reader = Cursor::new(buf);

    let mut AvailableIn = 0;
    let mut AvailableOut = kFileBufferSize;
    let mut result = BrotliDecoderResult_BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
    let mut out_pointer = next_out.as_mut_ptr();
    let mut in_pointer = next_in.as_ptr();
    in_reader.seek(std::io::SeekFrom::Start(DECODE_HEADER_SIZE as u64))?;
    let mut dummy_scratch_buffer_size = 0usize;

    unsafe {
        let state = BrotliDecoderCreateInstance(
            Some(BrotliAllocFunc),
            Some(BrotliFreeFunc),
            ScratchBufferSize.unwrap_or(&mut dummy_scratch_buffer_size) as *mut usize
                as *mut ::std::os::raw::c_void,
        );
        defer!(BrotliDecoderDestroyInstance(state));
        if state.is_null() {
            return Err(crate::Error::OutOfMemory);
        }
        /* This allows decoding "large-window" streams. Though it creates
        fragmentation (new builds decode streams that old builds don't),
        it is better from used experience perspective. */
        BrotliDecoderSetParameter(
            state,
            BrotliDecoderParameter_BROTLI_DECODER_PARAM_LARGE_WINDOW,
            1u32,
        );

        loop {
            if result == BrotliDecoderResult_BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT {
                if is_reader_eof(&mut in_reader)? {
                    return Err(crate::Error::UnexpectedEndOfBuffer);
                }
                AvailableIn = in_reader.read(&mut next_in)?;
                in_pointer = next_in.as_ptr();
            } else if result == BrotliDecoderResult_BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT {
                let out_size = out_pointer as usize - next_out.as_ptr() as usize;
                if out_size > 0 {
                    out_writer.write_all(&next_out[..out_size])?;
                }
                AvailableOut = kFileBufferSize;
                out_pointer = next_out.as_mut_ptr();
            } else if result == BrotliDecoderResult_BROTLI_DECODER_RESULT_SUCCESS {
                let out_size = out_pointer as usize - next_out.as_ptr() as usize;
                if out_size > 0 {
                    out_writer.write_all(&next_out[..out_size])?;
                }
                AvailableOut = 0;
                if AvailableIn != 0 || !is_reader_eof(&mut in_reader)? {
                    return Err(crate::Error::UnexpectedEndOfBuffer);
                }
            } else {
                return Err(crate::Error::I32(result as i32));
            }

            if is_reader_eof(&mut in_reader)?
                && result == BrotliDecoderResult_BROTLI_DECODER_RESULT_SUCCESS
            {
                break;
            }
            result = BrotliDecoderDecompressStream(
                state,
                &mut AvailableIn as *mut usize,
                &mut in_pointer as *mut *const u8,
                &mut AvailableOut as *mut usize,
                &mut out_pointer as *mut *mut u8,
                null_mut(),
            );
        }
    }
    Ok(out_buf)
}

fn is_reader_eof(reader: &mut impl BufRead) -> std::io::Result<bool> {
    Ok(reader.fill_buf()?.is_empty())
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(target_os = "windows")]
    const TOOL_NAME: &str = "BrotliCompress.exe";
    #[cfg(not(target_os = "windows"))]
    const TOOL_NAME: &str = "BrotliCompress";

    /// Due to bortli_enc does not produce the same result with BortliCompress.exe
    /// So the goal of this test is to make sure the produced compress data
    /// can be decompressed with BortliCompress.exe
    #[test]
    fn test_brotli() {
        let test_path = std::env::current_dir().unwrap().join("test");
        let test_reference_bin_name = "brotli_compressed.bin";
        let test_reference_bin = test_path.join(test_reference_bin_name);
        let test_reference_dec_bin_name = "brotli_decompressed.bin";
        let test_reference_dec_bin = test_path.join(test_reference_dec_bin_name);

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }
        if test_reference_dec_bin.exists() {
            std::fs::remove_file(&test_reference_dec_bin).unwrap();
        }

        let test_src = crate::test::get_test_file();

        let compressed = brotli_enc(test_src.slice()).unwrap();
        std::fs::write(&test_reference_bin, &compressed).unwrap();
        assert!(std::process::Command::new(test_path.join(TOOL_NAME))
            .arg("-d")
            .arg(test_reference_bin.as_os_str())
            .arg("-o")
            .arg(test_reference_dec_bin.as_os_str())
            .current_dir(test_path.as_os_str())
            .status()
            .unwrap()
            .success());

        let decompressed = brotli_dec(&compressed).unwrap();
        assert_eq!(test_src.slice().len(), decompressed.len());
        assert!(test_src.slice().eq(&decompressed));

        let reference_buf = std::fs::read(test_path.join(&test_reference_dec_bin)).unwrap();
        assert_eq!(reference_buf.len(), decompressed.len());
        assert!(reference_buf.eq(&decompressed));

        if test_reference_bin.exists() {
            std::fs::remove_file(&test_reference_bin).unwrap();
        }
        if test_reference_dec_bin.exists() {
            std::fs::remove_file(&test_reference_dec_bin).unwrap();
        }
    }

    #[test]
    fn test_eof() {
        let buf = [0, 0, 1, 1];
        let mut cursor = Cursor::new(buf);
        let mut read_buf = [0];
        assert!(!is_reader_eof(&mut cursor).unwrap());
        cursor.read(&mut read_buf).unwrap();
        assert!(!is_reader_eof(&mut cursor).unwrap());
        cursor.read(&mut read_buf).unwrap();
        assert!(!is_reader_eof(&mut cursor).unwrap());
        cursor.read(&mut read_buf).unwrap();
        assert!(!is_reader_eof(&mut cursor).unwrap());
        cursor.read(&mut read_buf).unwrap();
        assert!(is_reader_eof(&mut cursor).unwrap());
    }
}
