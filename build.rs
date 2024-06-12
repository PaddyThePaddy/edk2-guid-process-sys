use std::env;
use std::path::PathBuf;

fn main() {
    let path_sep = if std::env::consts::OS == "windows" {
        "\\"
    } else {
        "/"
    };
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=src{path_sep}wrapper.h");
    println!("cargo:rerun-if-changed=src{path_sep}edk2{path_sep}Common");
    println!("cargo:rerun-if-changed=src{path_sep}edk2{path_sep}Include");
    println!("cargo:rerun-if-changed=src{path_sep}edk2{path_sep}LzmaCompress");
    println!("cargo:rerun-if-changed=src{path_sep}edk2{path_sep}TianoCompress");
    println!("cargo:rerun-if-changed=src{path_sep}edk2{path_sep}BrotliCompress");
    println!("cargo:rerun-if-changed=src{path_sep}edk2{path_sep}GenCrc32");

    let mut lzma_build = cc::Build::new();
    lzma_build
        .file("src/edk2/LzmaCompress/Sdk/C/7zFile.c")
        .file("src/edk2/LzmaCompress/Sdk/C/7zStream.c")
        .file("src/edk2/LzmaCompress/Sdk/C/Alloc.c")
        .file("src/edk2/LzmaCompress/Sdk/C/Bra86.c")
        .file("src/edk2/LzmaCompress/Sdk/C/LzFind.c")
        .file("src/edk2/LzmaCompress/Sdk/C/LzmaDec.c")
        .file("src/edk2/LzmaCompress/Sdk/C/LzmaEnc.c")
        .file("src/edk2/Common/CommonLib.c")
        .file("src/edk2/Common/EfiUtilityMsgs.c")
        .flag("-Isrc/edk2/Common")
        .flag("-Isrc/edk2/Include/X64")
        .flag("-Isrc/edk2/Include");

    if std::env::consts::OS == "windows" {
        lzma_build
            .file("src/edk2/LzmaCompress/Sdk/C/Threads.c")
            .file("src/edk2/LzmaCompress/Sdk/C/LzFindMt.c");
    } else {
        lzma_build.flag("-D_7ZIP_ST");
    }

    lzma_build.compile("lzmacompress");

    cc::Build::new()
        .file("src/edk2/TianoCompress/TianoCompress.c")
        .file("src/edk2/Common/ParseInf.c")
        .flag("-Isrc/edk2/Common")
        .flag("-Isrc/edk2/Include/X64")
        .flag("-Isrc/edk2/Include")
        .compile("tianocompress");

    cc::Build::new()
        .file("src/edk2/Common/Decompress.c")
        .file("src/edk2/Common/EfiCompress.c")
        .flag("-Isrc/edk2/Common")
        .flag("-Isrc/edk2/Include/X64")
        .flag("-Isrc/edk2/Include")
        .compile("eficompress");

    cc::Build::new()
        .file("src/edk2/BrotliCompress/BrotliCompress.c")
        .file("src/edk2/BrotliCompress/brotli/c/common/constants.c")
        .file("src/edk2/BrotliCompress/brotli/c/common/context.c")
        .file("src/edk2/BrotliCompress/brotli/c/common/dictionary.c")
        .file("src/edk2/BrotliCompress/brotli/c/common/platform.c")
        .file("src/edk2/BrotliCompress/brotli/c/common/shared_dictionary.c")
        .file("src/edk2/BrotliCompress/brotli/c/common/transform.c")
        .file("src/edk2/BrotliCompress/brotli/c/dec/bit_reader.c")
        .file("src/edk2/BrotliCompress/brotli/c/dec/decode.c")
        .file("src/edk2/BrotliCompress/brotli/c/dec/huffman.c")
        .file("src/edk2/BrotliCompress/brotli/c/dec/state.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/command.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/compound_dictionary.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/backward_references.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/fast_log.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/backward_references_hq.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/bit_cost.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/block_splitter.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/brotli_bit_stream.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/cluster.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/compress_fragment.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/compress_fragment_two_pass.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/dictionary_hash.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/encode.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/encoder_dict.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/entropy_encode.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/histogram.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/literal_cost.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/memory.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/metablock.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/static_dict.c")
        .file("src/edk2/BrotliCompress/brotli/c/enc/utf8_util.c")
        .flag("-Isrc/edk2/BrotliCompress/brotli/c/include")
        .compile("brotlicompress");

    cc::Build::new()
        .file("src/edk2/GenCrc32/GenCrc32.c")
        .file("src/edk2/Common/Crc32.c")
        .flag("-Isrc/edk2/Include")
        .flag("-Isrc/edk2/Common")
        .flag("-Isrc/edk2/Include/X64")
        .compile("crc32");

    // Tell cargo to look for shared libraries in the specified directory
    //println!("cargo:rustc-link-search=/path/to/lib");

    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    //println!("cargo:rustc-link-lib=bz2");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/wrapper.h")
        .clang_args(["-I", "src/edk2/Include"])
        .clang_args(["-I", "src/edk2/Include/X64"])
        .clang_args(["-I", "src/edk2/Common"])
        .clang_args(["-I", "src/edk2/BrotliCompress/brotli/c/include"])
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
