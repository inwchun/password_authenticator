
/*
 * NIPP for generating proofs
**/

use chrono::{DateTime, Utc};
use cookie_factory;
use crate::tools::prompt;
// use std::convert::TryInto;
use openssl::ec::{
    EcKey, EcGroup, EcPoint, PointConversionForm, EcPointRef
};
use openssl;
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::Private;
use openssl::bn::{BigNum, BigNumContext};
use openssl::nid::Nid;
use sha2::{Sha256, Digest};
use openssl::rand::rand_bytes;
use openssl::pkcs5::pbkdf2_hmac;
use rand::Rng;
use std::time::Instant;
// use std::fs::OpenOptions;
use std::io::prelude::*;
use std::fs::File;

static ITERATIONS: usize = 100_000;
// static FILENAME: &str = "./test/result/rusttest.txt";

pub fn setup(password: &[u8]) -> (Vec<u8>,(Vec<u8>, Vec<u8>)) {
        log!("---SETUP START---");
    let salt = get_random();
    let (sk, pk) = keyconstruct(password, &salt);
    let pp = salt;
    let vk = pk;
    (pp, vk)
}

pub fn keyconstruct(password: &[u8], salt: &[u8]) -> (EcKey<Private>, (Vec<u8>, Vec<u8>)) {
    let x = hash_slow(&password ,&salt, ITERATIONS);
    let sk = generate_privkey(&x);
    let pk = get_pubkey(&sk);
    (sk, pk)
}

pub fn signprime(sk: EcKey<Private>, m: &[u8]) -> Vec<u8>  {
    let pk = get_pubkey(&sk);
    let m_pk = [&pk.0[..], &pk.1[..]].concat();
    let r = get_random();
    let p = get_randomp();
    let t_pzl = hash_pepper(&m_pk, &r, &p, ITERATIONS);
    let m_sigma = hash_pepper(&[m, &m_pk].concat(), &r, &p, ITERATIONS);
    let sign = sign(&sk, &m_sigma);
    let signprime = [&sign[..], &t_pzl[..], &r[..]].concat();
    signprime
}

pub fn prove(password: &[u8], pp: &[u8], message: &[u8]) -> Vec<u8> {
        let mut FILENAME: String = "./result".to_owned();
        FILENAME.push_str(ITERATIONS.to_string().as_str());
        FILENAME.push_str(".txt");
        let mut file = File::options()
        .write(true)
        .append(true)
        .create(true)
        .open(FILENAME.as_str())
        .unwrap();

    let salt = pp;
        let key_start = Instant::now();
    let (sk, pk) = keyconstruct(password ,salt);
        let key_end = Instant::now();

        let sign_start = Instant::now();
    let signprime = signprime(sk, message);
        let sign_end = Instant::now();
        
        writeln!(file, "{:?} {:?}", key_end.duration_since(key_start).as_millis(), sign_end.duration_since(sign_start).as_micros());

    let proof = signprime;
    proof

}

pub fn get_random() -> Vec<u8> {
    let mut bytes : Vec<u8> = [0u8;16].to_vec();
    rand_bytes(&mut bytes).unwrap();
    bytes.to_vec()
}

pub fn get_randomp() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let k_u16 :u16 = rng.gen_range(0..4095);
    // let u1 : u8 = ((k_u32 >> 24) & 0xff) as u8;
    // let u2 : u8 = ((k_u32 >> 16) & 0xff) as u8;
    let u1 : u8 = ((k_u16 >> 8) & 0xff) as u8;
    let u2 : u8 = (k_u16 & 0xff) as u8;
    // [u1, u2, u3, u4].to_vec()
    [u1, u2].to_vec()
}

pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let result = Sha256::digest(data).to_vec();
    result
}

pub fn generate_privkey(scalar: &[u8]) -> EcKey<Private> {
    //TODO: mod and if 0
    let ecgroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let bignum = BigNum::from_slice(scalar).unwrap();
    let mut ecpoint = EcPoint::new(&ecgroup).unwrap();
    let bignumctx = BigNumContext::new().unwrap();
    EcPointRef::mul_generator(&mut ecpoint, &ecgroup, &bignum, &bignumctx).unwrap();
    let privkey = EcKey::from_private_components(&ecgroup, &bignum, &ecpoint).unwrap();
    privkey
}

pub fn get_pubkey(privkey:  &EcKey<Private>) -> (Vec<u8>, Vec<u8>) {
    let ecgroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let pubkey = privkey.public_key();
    let mut bignumctx = BigNumContext::new().unwrap();
    let form = PointConversionForm::UNCOMPRESSED;
    let point = pubkey.to_bytes(&ecgroup, form, &mut bignumctx).unwrap();
    xy_point(&point)
}

pub fn sign(privkey: &EcKey<Private>, message: &[u8]) -> Vec<u8> {
    let hash = hash_sha256(message);
    let signature = EcdsaSig::sign(&hash, &privkey).unwrap();
    let r = signature.r().to_vec();
    let s = signature.s().to_vec();
    encode_signature(&r, &s)
}

pub fn hash_pepper(g_x: &[u8], salt_t: &[u8], p: &[u8], iterations: usize) -> Vec<u8> {
    let mut key = [0u8;32];
    let data = &[&g_x[..], &p[..]].concat();
    pbkdf2_hmac(
        data,
        salt_t,
        iterations / 4096 + 1,
        openssl::hash::MessageDigest::sha256(),
        &mut key,
    ).unwrap();
    key.to_vec()
}

pub fn hash_slow(password: &[u8], salt_x: &[u8], iterations: usize) -> Vec<u8> {
    let mut key = [0u8;32];
    pbkdf2_hmac(
        password,
        salt_x,
        iterations,
        openssl::hash::MessageDigest::sha256(),
        &mut key,
    ).unwrap();
    key.to_vec()
}

pub fn bitwise_xor(v1:&[u8], v2: &[u8]) -> Vec<u8> {
    v1
    .iter()
    .zip(v2.iter())
    .map(|(&x1, &x2)| x1 ^ x2)
    .collect()  
}

fn xy_point (point: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert!(point.len() == 65, "invalid length");
    assert!(point[0] == 0x04, "point not in uncompressed format");
    let (x, y) = (point[1..33].to_vec(), point[33..].to_vec());
    (x, y)
}

fn encode_signature (r: &[u8], s: &[u8]) -> Vec<u8> {
    assert!(r.len() <= 32);
    assert!(s.len() <= 32);
    fn encode_integer (mut int: &[u8], out: &mut Vec<u8>) {
        out.push(0x02);
        int = &int[int.iter().position(|&i| i != 0).unwrap() ..];
        if int[0] & 0x80 != 0 {   // would be interpreted as sign flag
            out.push(int.len() as u8 + 1); // so insert an extra zero
            out.push(0);
        } else {
            out.push(int.len() as u8);
        };
        out.extend_from_slice(int)
    }
    let mut out = vec![0x30u8, 0];
    encode_integer(r, &mut out);
    encode_integer(s, &mut out);
    out[1] = out.len() as u8 - 2;
    out
}

