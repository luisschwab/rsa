use rsa::io;
use rsa::key;
use rsa::sig;
use rsa::sig::sign;
use std::fs::read;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    /*
    println!("Generating keys...");
    let t0 = Instant::now();
    let key_pair = generate_keypair();
    let duration = t0.elapsed().as_secs_f64();
    println!("Generated a {} bit RSA key in {:.2} seconds", 2*key::PRIME_LENGHT, duration);
    println!("{}", key_pair);

    let message = "rsa".as_bytes();
    println!("message: {}", print_bytes(&message));

    let label = LABEL;
    let k = ((key_pair.n.bits() + 7) / 8) as usize;
    let padded = oaep_pad(message, label, k).unwrap();
    println!("padded: {}", print_bytes(&padded));

    let cipher = cipher(&padded, &key_pair.n, &key_pair.e).unwrap();
    println!("cipher: {}", print_bytes(&cipher));

    let deciphered = decipher(&cipher, &key_pair.n, &key_pair.d).unwrap();
    println!("deciphered: {}", print_bytes(&deciphered));

    let unpadded = oaep_unpad(&deciphered, label).unwrap();
    println!("unpadded: {}", print_bytes(&unpadded));

    let signature = sign(message, &key_pair.n, &key_pair.d);
    println!("signature: {}", print_bytes(&signature));

    let verified = verify(message, &signature, &key_pair.n, &key_pair.e);
    println!("verified: {}", if verified {"true"} else {"false"});
    */

    println!("The Rivest-Shamir-Adleman public-key cryptosystem");
    println!("Generates keys, encrypts, decrypts, signs and verifies stuff.\n");

    // clean file directory
    io::clean_dir()?;

    // generate keys
    println!("Generating keys...");
    let t0 = Instant::now();
    let keypair = key::generate_keypair();
    let duration = t0.elapsed().as_secs_f64();
    println!(
        "Generated a {} bit RSA key in {:.2} seconds",
        2 * key::PRIME_LENGHT,
        duration
    );
    println!("\n{}\n", keypair);

    // write keys to disk, base64 encoded
    io::write_keypair(&keypair, io::BASE_PATH)?;
    println!(
        "Wrote keys to [{}] and [{}]",
        io::BASE_PATH.to_owned() + io::FILE_PRIVKEY,
        io::BASE_PATH.to_owned() + io::FILE_PUBKEY
    );

    // ENCRYPTION / DECRYPTION
    // cipher and write to disk
    let message_path = io::BASE_PATH.to_owned() + io::FILE_CLEARTEXT;
    let cipher_path = io::BASE_PATH.to_owned() + io::FILE_CIPHERTEXT;
    io::encrypt_file(&message_path, &cipher_path, &keypair)?;
    println!(
        "Wrote cipher to [{}]",
        io::BASE_PATH.to_owned() + io::FILE_CIPHERTEXT
    );

    // read from disk, decipher and write to disk
    let deciphered_path = io::BASE_PATH.to_owned() + io::FILE_DECIPEHRED;
    io::decrypt_file(&cipher_path, &deciphered_path, &keypair)?;
    println!(
        "Wrote deciphered to [{}]",
        io::BASE_PATH.to_owned() + io::FILE_DECIPEHRED
    );

    // assert message and deciphered are equal
    assert_eq!(read(message_path.clone())?, read(deciphered_path.clone())?);
    println!(
        "[{}] is byte-wise identical to [{}]!",
        message_path.clone(),
        deciphered_path
    );

    // SIGN / VERIFY
    // sign and write to disk
    let message = read(message_path)?;
    let signature = sign(&message, &keypair.n, &keypair.d);
    let signature_path = io::BASE_PATH.to_owned() + io::FILE_SIGNATURE;
    io::write_signature(&signature, &signature_path)?;
    println!("Wrote signature to [{}]", &signature_path);

    // read from disk and verify
    let signature = io::read_signature(&signature_path)?;
    let valid_sig = sig::verify(&message, &signature, &keypair.n, &keypair.e);
    assert_eq!(valid_sig, true);
    println!("The signature produced is valid!");

    Ok(())
}
