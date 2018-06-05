use openssl::pkcs5::pbkdf2_hmac;
use openssl::symm;
use openssl::hash;
use rand::{OsRng, RngCore};
use std::str;

fn crypt_opt(mode: symm::Mode, key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut crypter = symm::Crypter::new(symm::Cipher::aes_256_cbc(),mode, key, Some(iv)).unwrap();
    
    let mut final_result = Vec::new();
    let mut count = crypter.update(data, &mut final_result).unwrap();
    count += crypter.finalize(&mut final_result).unwrap();
    final_result.truncate(count);

    final_result
}

pub type Iv = Vec<u8>;
pub fn encrypt(key: &[u8], string: &str) -> (Iv, Vec<u8>) {
    let iv = gen_bytes();
    let data: Vec<u8> = string.bytes().collect();

    (iv.clone(), crypt_opt(symm::Mode::Encrypt, key, &iv, &data))
}

pub fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> String {
    let result = crypt_opt(symm::Mode::Decrypt, key, iv, data);
    str::from_utf8(&result).ok().unwrap_or("").to_owned()
}

pub fn derive_key(p: &[u8], salt: &[u8]) -> Vec<u8> {
  let mut key = Vec::new();
    pbkdf2_hmac(p, salt, 1024, hash::MessageDigest::sha256(), &mut key).unwrap();
  key
}

pub fn gen_bytes() -> Vec<u8> {
    let mut salt = [0; 16];
    let mut f = OsRng::new().ok().expect("Unable to use OS Rng. Can't save");

    f.fill_bytes(&mut salt);
    salt.to_vec()
}
