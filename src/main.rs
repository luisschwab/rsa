mod cipher;
mod util;
mod keygen;

use cipher::*;
use util::print_bytes;
use keygen::*;

// the default value for the OAEP label is an empty string
const LABEL: &[u8] = &[0x21];

fn main() {
    let key_pair = generate_keypair();
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
}
