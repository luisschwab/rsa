mod keygen;

use keygen::*;

fn main() {
    let key_pair = generate_keypair();

    println!("{}", key_pair);
}
