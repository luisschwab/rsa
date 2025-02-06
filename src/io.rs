//! I/O operations
//!
//! Read Cleartext File
//! Write Encrypted File
//! Read/Write Keys
//! Read/Write Signature

use crate::cipher::*;
use crate::key::KeyPair;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use num_bigint::BigUint;
use std::fs;
use std::path::Path;

pub const BASE_PATH: &str = "files/";
// pub const FILE_CLEARTEXT: &str = "whitepaper.pdf";
// pub const FILE_CIPHERTEXT: &str = "whitepaper.rsa";
pub const FILE_CLEARTEXT: &str = "test.txt";
pub const FILE_CIPHERTEXT: &str = "test.rsa";
pub const FILE_DECIPEHRED: &str = "test.rsa.deciphered";
pub const FILE_SIGNATURE: &str = "test.sig";

pub const FILE_PUBKEY: &str = "public.pem";
pub const FILE_PRIVKEY: &str = "private.pem";

pub fn print_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Clean file directory
pub fn clean_dir() -> std::io::Result<()> {
    let dir = Path::new(BASE_PATH);
    if dir.exists() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.file_name().unwrap() != FILE_CLEARTEXT {
                if path.is_file() {
                    fs::remove_file(path)?;
                }
            }
        }
    }
    Ok(())
}

/// Writes keys to FILE_{PUBKEY,PRIVKEY}
pub fn write_keypair(keypair: &KeyPair, dir: &str) -> std::io::Result<()> {
    // Create directory if it doesn't exist
    fs::create_dir_all(dir)?;

    // pubkey (n, e)
    let mut pub_data = keypair.n.to_bytes_be();
    pub_data.extend(keypair.e.to_bytes_be());
    let pub_b64 = STANDARD.encode(&pub_data);
    let pub_pem = format!(
        "-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----\n",
        pub_b64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<&str>>()
            .join("\n")
    );
    fs::write(Path::new(dir).join(FILE_PUBKEY), pub_pem)?;

    // privkey (n, d)
    let mut priv_data = keypair.n.to_bytes_be();
    priv_data.extend(keypair.d.to_bytes_be());
    let priv_b64 = STANDARD.encode(&priv_data);
    let priv_pem = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
        priv_b64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<&str>>()
            .join("\n")
    );
    fs::write(Path::new(dir).join(FILE_PRIVKEY), priv_pem)?;

    Ok(())
}

/// Reads keys from FILE_{PUBKEY. PRIVKEY}
pub fn read_keypair(dir: &str) -> std::io::Result<KeyPair> {
    // read pubkey
    let pub_pem = fs::read_to_string(Path::new(dir).join(FILE_PUBKEY))?;
    let pub_b64 = pub_pem
        .lines()
        .filter(|line| !line.contains("BEGIN") && !line.contains("END"))
        .collect::<String>();
    let pub_data = STANDARD.decode(pub_b64).unwrap();

    // read privkey
    let priv_pem = fs::read_to_string(Path::new(dir).join(FILE_PRIVKEY))?;
    let priv_b64 = priv_pem
        .lines()
        .filter(|line| !line.contains("BEGIN") && !line.contains("END"))
        .collect::<String>();
    let priv_data = STANDARD.decode(priv_b64).unwrap();

    let key_len = pub_data.len() / 2;

    Ok(KeyPair {
        n: BigUint::from_bytes_be(&pub_data[..key_len]),
        e: BigUint::from_bytes_be(&pub_data[key_len..]),
        d: BigUint::from_bytes_be(&priv_data[key_len..]),
    })
}

/// Encrypt file and write to FS
pub fn encrypt_file(
    message_path: &str,
    cipher_path: &str,
    keypair: &KeyPair,
) -> std::io::Result<()> {
    let message = fs::read(message_path)?;

    // Get key length and pad message
    let k = (keypair.n.bits() as usize + 7) / 8;
    let padded = oaep_pad(&message, LABEL, k).unwrap();

    // Encrypt
    let encrypted = cipher(&padded, &keypair.n, &keypair.e).unwrap();

    // Write encrypted data in PEM format
    let enc_b64 = STANDARD.encode(&encrypted);
    let enc_pem = format!(
        "-----BEGIN RSA ENCRYPTED MESSAGE-----\n{}\n-----END RSA ENCRYPTED MESSAGE-----\n",
        enc_b64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<&str>>()
            .join("\n")
    );

    fs::write(cipher_path, enc_pem)
}

/// Read encrypted file from FS and write to FS
pub fn decrypt_file(
    cipher_path: &str,
    deciphered_path: &str,
    keypair: &KeyPair,
) -> std::io::Result<()> {
    // Read encrypted PEM file
    let enc_pem = fs::read_to_string(cipher_path)?;
    let enc_b64 = enc_pem
        .lines()
        .filter(|line| !line.contains("BEGIN") && !line.contains("END"))
        .collect::<String>();
    let encrypted = STANDARD.decode(enc_b64).unwrap();

    // Decrypt
    let decrypted = decipher(&encrypted, &keypair.n, &keypair.d).unwrap();
    let message = oaep_unpad(&decrypted, LABEL).unwrap();

    // Write decrypted data
    fs::write(deciphered_path, message)
}

/// Write signature to <path>.sig
pub fn write_signature(signature: &[u8], path: &str) -> std::io::Result<()> {
    let sig_b64 = STANDARD.encode(signature);
    let sig_pem = format!(
        "-----BEGIN RSA SIGNATURE-----\n{}\n-----END RSA SIGNATURE-----\n",
        sig_b64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<&str>>()
            .join("\n")
    );

    fs::write(path, sig_pem)
}

/// Read signature from <path>.sig
pub fn read_signature(path: &str) -> std::io::Result<Vec<u8>> {
    let sig_pem = fs::read_to_string(path)?;
    let sig_b64 = sig_pem
        .lines()
        .filter(|line| !line.contains("BEGIN") && !line.contains("END"))
        .collect::<String>();

    Ok(STANDARD.decode(sig_b64).unwrap())
}
