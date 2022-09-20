use pinentry_rs;
use std::sync::mpsc::{Receiver};
use secstr;
use secstr::SecVec;
use openssl::rand::rand_bytes;

fn escape_string(s: &str) -> String {
    let mut r = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => r.push_str("%0A"),
            c => r.push(c)
        }
    };
    r
}

pub fn get_password(prompt: &str)
                  -> Receiver<Result<secstr::SecStr, pinentry_rs::Error>> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let escaped = escape_string(prompt);
    std::thread::spawn(move || {
        let peb = pinentry_rs::pinentry().description(escaped);
        // let r = peb.pin((&"HanPass").to_string());
        let r = test_password();
        sender.send(r)//.unwrap()
    });
    receiver
}

pub fn random_password() -> Result<secstr::SecVec<u8>, pinentry_rs::Error> {
    let mut bytes : Vec<u8> = [0u8;10].to_vec();
    rand_bytes(&mut bytes).unwrap();
    Ok(SecVec::new(bytes.to_vec()))
}

pub fn test_password() -> Result<secstr::SecVec<u8>, pinentry_rs::Error> {
    let mut bytes : Vec<u8> = [0u8;10].to_vec();
    Ok(SecVec::new(bytes.to_vec()))
}