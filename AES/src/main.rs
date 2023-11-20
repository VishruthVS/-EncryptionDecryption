use crypto::aead::{AeadDecryptor, AeadEncryptor};
use crypto::aes_gcm::AesGcm;
use std::error::Error;
use std::io::ErrorKind;
use std::iter::repeat;
use std::str::from_utf8;
use std::{io, str};

//This function splits the data, removes the hex encoding, and returns each as a list of bytes.
fn split_iv_data_mac(orig: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let split: Vec<&str> = orig.split('/').into_iter().collect();

    if split.len() != 3 {
        return Err(Box::new(io::Error::from(ErrorKind::Other)));
    }

    let iv_res: Result<Vec<u8>, hex::FromHexError> = hex::decode(split[0]);
    if iv_res.is_err() {
        return Err(Box::new(io::Error::from(ErrorKind::Other)));
    }
    let iv: Vec<u8> = iv_res.unwrap();

    let data_res: Result<Vec<u8>, hex::FromHexError> = hex::decode(split[1]);
    if data_res.is_err() {
        return Err(Box::new(io::Error::from(ErrorKind::Other)));
    }
    let data: Vec<u8> = data_res.unwrap();

    let mac_res: Result<Vec<u8>, hex::FromHexError> = hex::decode(split[2]);
    if mac_res.is_err() {
        return Err(Box::new(io::Error::from(ErrorKind::Other)));
    }
    let mac: Vec<u8> = mac_res.unwrap();

    Ok((iv, data, mac))
}

fn get_valid_key(key: &str) -> Vec<u8> {
    let mut bytes = key.as_bytes().to_vec();
    if bytes.len() < 16 {
        for _j in 0..(16 - bytes.len()) {
            bytes.push(0x00);
        }
    } else if bytes.len() > 16 {
        bytes = bytes[0..16].to_vec();
    }

    bytes
}

pub fn decrypt(iv_data_mac: &str, key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let (iv, data, mac) = split_iv_data_mac(iv_data_mac)?;
    let key: Vec<u8> = get_valid_key(key);

    let key_size: crypto::aes::KeySize = crypto::aes::KeySize::KeySize128;

    let mut decipher: AesGcm<'_> = AesGcm::new(key_size, &key, &iv, &[]);

    let mut dst: Vec<u8> = repeat(0).take(data.len()).collect();
    let result = decipher.decrypt(&data, &mut dst, &mac);

    println!();

    if result {
        println!("Decryption Successful");
    }

    Ok(dst)
}

/// Output is [hexIV]/[hexCipher]/[hexMac]
pub fn encrypt(data: &[u8], key: &str) -> String {
    let key_size: crypto::aes::KeySize = crypto::aes::KeySize::KeySize128;

    let valid_key: Vec<u8> = get_valid_key(key);
    let mut iv: Vec<u8> = vec![];
    for _j in 0..12 {
        let r: u8 = rand::random();
        iv.push(r);
    }

    let mut cipher: AesGcm<'_> = AesGcm::new(key_size, &valid_key, &iv, &[]);

    let mut encrypted: Vec<u8> = repeat(0).take(data.len()).collect();

    let mut mac: Vec<u8> = repeat(0).take(16).collect();

    cipher.encrypt(data, &mut encrypted, &mut mac[..]);

    let hex_iv: String = hex::encode(iv);
    let hex_cipher: String = hex::encode(encrypted);
    let hex_mac: String = hex::encode(mac);
    let output: String = format!("{}/{}/{}", hex_iv, hex_cipher, hex_mac);

    println!("Cipher Text : {}", hex_cipher);

    output
}

fn main() {
    println!("Encryption and Decryption using Advanced Encryption Standard");
    println!();

    println!("List of Available Functions: ");
    println!("1. Encrypt");
    println!("2. Decrypt");
    println!("3. Exit");

    println!();

    println!("Enter your choice: ");

    let mut choice: String = String::new();

    let _nb: usize = io::stdin().read_line(&mut choice).unwrap();

    let mut plain_text: String = String::new();
    let mut key: String = String::new();
    let mut _cipher_text: String = String::new();

    println!();

    match choice.as_str().trim() {
        "1" => {
            println!("You have Selected to Encrypt Data");
            println!();

            println!("Enter the Plain Text: ");
            io::stdin().read_line(&mut plain_text).unwrap();
            println!();

            println!("Enter the Key: ");
            io::stdin().read_line(&mut key).unwrap();
            println!();

            println!("Data to be encrypted: {} and Key: {}", plain_text, key);

            println!("Encrypting The Data");

            let res: String = encrypt(plain_text.as_bytes(), key.as_str());
            println!();

            println!("Output: {}", res);
        }
        "2" => {
            println!("You have selected to Decrypt Data");
            println!();

            println!(
                "Enter the Initalization Vector, Cipher Text and Message Authentication Code in Hex: "
            );

            let mut input: String = String::new();
            io::stdin().read_line(&mut input).unwrap();

            println!();
            println!("Enter the Key: ");

            io::stdin().read_line(&mut key).unwrap();

            let decrypted_bytes: Vec<u8> = decrypt(input.as_str().trim(), key.as_str()).unwrap();
            let decrypted_string: &str = from_utf8(&decrypted_bytes).unwrap();

            println!("Plain Text: {}", decrypted_string);
        }
        "3" => {
            println!("Thank You");
            std::process::exit(0);
        }
        _ => {
            println!("Invalid Choice");
        }
    }
}
