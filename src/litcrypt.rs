//! # LitCrypt
//! The name is an abbreviation of ‘Literal Encryption’ – a Rust compiler plugin to encrypt
//! text literals using the [XOR cipher](https://en.wikipedia.org/wiki/XOR_cipher).
//!
//! LitCrypt let’s you hide your static string literal in the binary from naughty eyes and protect
//! your app from illegal cracking activity.
//!
//! LitCrypt works by encrypting string literals during compile time. An encrypted string remains
//! encrypted both on disk and in memory during runtime. It is decypted only when used.
//!
//! ## Usage
//! In `Cargo.toml`, add:
//!
//! ```toml
//! [dependencies]
//! litcrypt = "0.2"
//! ```
//!
//! # Example
//!
//! ```rust
//! #[macro_use]
//! extern crate litcrypt;
//!
//! use_litcrypt!("MY-SECRET-SPELL");
//!
//! fn main(){
//!     println!("his name is: {}", lc!("Voldemort"));
//! }
//! ```
//!
//! The [`use_litcrypt!`] macro must be called first, for initialization. Its parameter is the
//! secret key that is used to encrypt all [`lc!`]-wrapped string literal(s).
//! This key is also encrypted and will not visible in a static analyzer.
//!
//! Only after that can you use the [`lc!`] macro.
//!
//! You can also override the key using an environment variable `LITCRYPT_ENCRYPT_KEY` e.g:
//! ```bash
//! ❯ export LITCRYPT_ENCRYPT_KEY="myverysuperdupermegaultrasecretkey"
//! ```
//!
//! LitCrypt will statically encrypt every string encapsulated in an `lc!` macro.
//!
//! Check the output binary using the `strings` command, e.g:
//!
//! ```bash
//! ❯ strings target/debug/my_valuable_app | grep Voldemort
//! ```
//!
//! If the output is blank then the resp. strings in your app are safe from a static analyzer tool
//! like a hex editor.
//!
//! For an example see the `./examples` directory:
//!
//! ```bash
//! ❯ cargo run --example simple
//! ```
extern crate proc_macro;
extern crate proc_macro2;
extern crate rand;
extern crate quote;
extern crate regex;

#[cfg(test)]
#[macro_use(expect)]
extern crate expectest;

use proc_macro::{TokenStream, TokenTree};
use proc_macro2::Literal;
use rand::{rngs::OsRng, RngCore};
use quote::quote;
use regex::Regex;
use std::{env, fs::File, path::{Path, PathBuf}, io::Read, str};

mod xor;

#[inline(always)]
fn get_magic_spell() -> Vec<u8> {
    match env::var("LITCRYPT_ENCRYPT_KEY") {
        Ok(key) => {key.as_bytes().to_vec()},
        Err(_) => {
            let mut key = vec![0u8; 64];
            OsRng.fill_bytes(&mut key);
            key
        }
    }
}

/// Sets the encryption key used for encrypting subsequence strings wrapped in a [`lc!`] macro.
///
/// This key is also encrypted an  will not visible in a static analyzer.
#[proc_macro]
pub fn use_litcrypt(_tokens: TokenStream) -> TokenStream {
    let magic_spell = get_magic_spell();

    #[cfg(feature = "use_alloc")]
    let alloc_dep =  quote! {
        use alloc::string::String;
        use alloc::vec::Vec;
    };
    #[cfg(not(feature = "use_alloc"))]
    let alloc_dep =  quote! {
    };

    let encdec_func = quote! {
        pub mod litcrypt_internal {
            #alloc_dep
            
            // This XOR code taken from https://github.com/zummenix/xor-rs
            /// Returns result of a XOR operation applied to a `source` byte sequence.
            ///
            /// `key` will be an infinitely repeating byte sequence.
            pub fn xor(source: &[u8], key: &[u8]) -> Vec<u8> {
                match key.len() {
                    0 => source.into(),
                    1 => xor_with_byte(source, key[0]),
                    _ => {
                        let key_iter = InfiniteByteIterator::new(key);
                        source.iter().zip(key_iter).map(|(&a, b)| a ^ b).collect()
                    }
                }
            }

            /// Returns result of a XOR operation applied to a `source` byte sequence.
            ///
            /// `byte` will be an infinitely repeating byte sequence.
            pub fn xor_with_byte(source: &[u8], byte: u8) -> Vec<u8> {
                source.iter().map(|&a| a ^ byte).collect()
            }

            struct InfiniteByteIterator<'a> {
                bytes: &'a [u8],
                index: usize,
            }

            impl<'a> InfiniteByteIterator<'a> {
                pub fn new(bytes: &'a [u8]) -> InfiniteByteIterator<'a> {
                    InfiniteByteIterator {
                        bytes: bytes,
                        index: 0,
                    }
                }
            }

            impl<'a> Iterator for InfiniteByteIterator<'a> {
                type Item = u8;
                fn next(&mut self) -> Option<u8> {
                    let byte = self.bytes[self.index];
                    self.index = next_index(self.index, self.bytes.len());
                    Some(byte)
                }
            }

            fn next_index(index: usize, count: usize) -> usize {
                if index + 1 < count {
                    index + 1
                } else {
                    0
                }
            }

            pub fn decrypt_bytes(encrypted: &[u8], encrypt_key: &[u8]) -> String {
                let decrypted = xor(&encrypted[..], &encrypt_key);
                String::from_utf8(decrypted).unwrap()
            }
        }
    };
    let result = {
        let ekey = xor::xor(&magic_spell, b"l33t");
        let ekey = Literal::byte_string(&ekey);
        quote! {
            static LITCRYPT_ENCRYPT_KEY: &'static [u8] = #ekey;
            #encdec_func
        }
    };
    result.into()
}

/// Encrypts the resp. string with the key set before, via calling [`use_litcrypt!`].
#[proc_macro]
pub fn lc(tokens: TokenStream) -> TokenStream {
    let mut something = String::from("");
    for tok in tokens {
        something = match tok {
            TokenTree::Literal(lit) => lit.to_string(),
            _ => "<unknown>".to_owned(),
        }
    }
    if something.starts_with("r#\"") {
        // Case raw string r#"..."#
        something = String::from(&something[3..something.len() - 2]);
    } else if something.starts_with("r\"") {
        // Case raw string r"..."
        something = String::from(&something[2..something.len() - 1]);
    } else {
        // try to reinterpret in case if escapes
        something = String::from(&something[1..something.len() - 1]);
        something = interpret_escapes(&something);
    }
    
    
    encrypt_string(something)
}

/// Encrypts an environment variable at compile time with the key set before, via calling [`use_litcrypt!`].
#[proc_macro]
pub fn lc_env(tokens: TokenStream) -> TokenStream {
    let mut var_name = String::from("");

    for tok in tokens {
        var_name = match tok {
            TokenTree::Literal(lit) => lit.to_string(),
            _ => "<unknown>".to_owned(),
        }
    }

    var_name = String::from(&var_name[1..var_name.len() - 1]);

    encrypt_string(env::var(var_name).unwrap_or(String::from("unknown")))
}

/// Encrypts text file contents with the key set before, via calling [`use_litcrypt!`].
#[proc_macro]
pub fn lc_text_file(tokens: TokenStream) -> TokenStream {
    let mut file_name = String::from("");

    for tok in tokens {
        file_name = match tok {
            TokenTree::Literal(lit) => lit.to_string(),
            _ => "<unknown>".to_owned(),
        }
    }

    file_name = String::from(&file_name[1..file_name.len() - 1]);
    // let span = proc_macro::Span::call_site();
    let path = match env::var("CARGO_MANIFEST_DIR") {
        Ok(path) => path,
        Err(_) => std::env::current_dir().unwrap().to_str().unwrap().to_string(),
    };
    let path = match resolve_path2(/*file!()*/ &path, &file_name) {
        Ok(x) => x,
        Err(msg) => {
            panic!("{} in lc_text_file!({:?})", msg, file_name);
        }
    };
    
    encrypt_string(load_file_str(&path).unwrap().to_string())
}

fn encrypt_string(something: String) -> TokenStream {
    let magic_spell = get_magic_spell();
    let encrypt_key = xor::xor(&magic_spell, b"l33t");
    let encrypted = xor::xor(&something.as_bytes(), &encrypt_key);
    let encrypted = Literal::byte_string(&encrypted);

    let result = quote! {
        crate::litcrypt_internal::decrypt_bytes(#encrypted, crate::LITCRYPT_ENCRYPT_KEY)
    };

    result.into()
}

fn interpret_escapes(input: &str) -> String {
    let re = Regex::new(r#"\\([ntrb\\'\"vf])"#).unwrap();

    re.replace_all(input, |caps: &regex::Captures| {
        match &caps[1] {
            "n" => "\n".to_string(),
            "t" => "\t".to_string(),
            "r" => "\r".to_string(),
            "b" => "\x08".to_string(),
            "\\" => "\\".to_string(),
            "'" => "'".to_string(),
            "\"" => "\"".to_string(),
            "f" => "\x0C".to_string(),
            "v" => "\x0B".to_string(),
            _ => caps[0].to_string(),
        }
    }).to_string()
}


#[doc(hidden)]
fn load_file_bytes(path: &Path) -> Result<&'static [u8], &'static str> {
    let mut f = File::open(path).map_err(|_| "file not found")?;

    let mut contents = Vec::new();
    f.read_to_end(&mut contents)
        .map_err(|_| "unable to read the file")?;

    let contents = contents.into_boxed_slice();
    Ok(Box::leak(contents))
}

#[doc(hidden)]
fn load_file_str(path: &Path) -> Result<&'static str, &'static str> {
    let bytes = load_file_bytes(path)?;
    let s = str::from_utf8(bytes).map_err(|_| "invalid utf8")?;
    Ok(s)
}

#[allow(dead_code)]
#[doc(hidden)]
fn resolve_path(base: &str, rel: &str) -> Result<PathBuf, &'static str> {
    Ok(Path::new(base)
        .parent()
        .ok_or("invalid source file path")?
        .join(rel))
}

#[doc(hidden)]
fn resolve_path2(base: &str, rel: &str) -> Result<PathBuf, &'static str> {
    Ok(Path::new(base)
        .join(rel))
}