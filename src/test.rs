use crate::tools::protocol::{hash_slow, hash_pepper, generate_privkey, get_pubkey, get_random, get_randomp, sign};
use std::time::Instant;
use openssl::rand::rand_bytes;
use openssl::ec::{
    EcKey, EcGroup, EcPoint, PointConversionForm, EcPointRef
};
use std::io::prelude::*;
use std::fs::File;
use openssl::pkey::Private;

static rounds: usize = 100;

pub fn latencytest() {
    test(10_000);
    test(100_000);
    test(320_000);
    test(390_000);    
}

fn test(iterations:usize) {
    let mut filename: String = "./result".to_owned();
    filename.push_str(iterations.to_string().as_str());
    filename.push_str(".txt");
    let mut file = File::options()
                    .write(true)
                    .append(true)
                    .create(true)
                    // .truncate(true)
                    .open(filename.as_str())
                    .unwrap();

    for i in 0..rounds {
        let (dummypw, dummypp, dummydata) = dummy_gen();
        // let dummyproof = prove_test(&dummypw, &dummypp, &dummydata, iterations);

        let keyconstruct_start = Instant::now();
        let (sk, pk) = keyconstruct_test(&dummypw, &dummypp, iterations);
        let keyconstruct_end = Instant::now();

        let sign_start = Instant::now();
        let signprime = signprime_test(sk, &dummydata, iterations);
        let sign_end = Instant::now();
            
        writeln!(file, "{:?} {:?}", keyconstruct_end.duration_since(keyconstruct_start).as_millis(), sign_end.duration_since(sign_start).as_micros());

        let dummyproof = signprime;
        log!("{}: {:?}",i ,dummyproof);
    }
}

pub fn keyconstruct_test(password: &[u8], salt: &[u8], iterations: usize) -> (EcKey<Private>, (Vec<u8>, Vec<u8>)) {
    let x = hash_slow(&password ,&salt, iterations);
    let sk = generate_privkey(&x);
    let pk = get_pubkey(&sk);
    (sk, pk)
}

pub fn signprime_test(sk: EcKey<Private>, m: &[u8], iterations: usize) -> Vec<u8>  {
    let pk = get_pubkey(&sk);
    let m_pk = [&pk.0[..], &pk.1[..]].concat();
    let r = get_random();
    let p = get_randomp();
    let t_pzl = hash_pepper(&m_pk, &r, &p, iterations);
    let m_sigma = hash_pepper(&[m, &m_pk].concat(), &r, &p, iterations);
    let sign = sign(&sk, &m_sigma);
    let signprime = [&sign[..], &t_pzl[..], &r[..]].concat();
    signprime
}



// pub fn setup_10000(password: &[u8]) -> (Vec<u8>,(Vec<u8>, Vec<u8>)) {
//     log!("---SETUP START---");
//     let salt_x = get_random();
//     // sk
//         let sk_start = Instant::now();
//     let x = hash_slow(&password ,&salt_x, 100_000);
//     let sk = generate_privkey(&x);
//         let sk_fin = Instant::now();
//         log!("sk_time: {:?}", sk_fin.duration_since(sk_start));
//     // let hpw = hash_sha256(password);
//         let vk_start = Instant::now();
//     let vk = get_pubkey(&sk);
//         let vk_fin = Instant::now();
//         log!("vk_time: {:?}", vk_fin.duration_since(vk_start));
//     // let pp = bitwise_xor(&hpw, &salt_x);
//     let pp = salt_x;
//         log!("---SETUP FINISH---");
//     (pp, vk)
// }

// pub fn prove_10000(password: &[u8], pp: &[u8], message: &[u8]) -> Vec<u8> {
//     let salt_x = pp;
//         log!("---PROVE START---");
//     // sk
//         let sk_start = Instant::now();
//     let x = hash_slow(&password, &salt_x, 100_000);
//     let sk = generate_privkey(&x);
//         let sk_fin = Instant::now();
//         log!("sk_time: {:?}", sk_fin.duration_since(sk_start));

//     let salt_t = get_random();
//     let p = get_randomp();

//     // g^x
//         let gx_start = Instant::now();
//     let pk = get_pubkey(&sk);   
//     let g_x = [&pk.0[..], &pk.1[..]].concat();
//         let gx_fin = Instant::now();
//         log!("gx_time: {:?}", gx_fin.duration_since(gx_start));

//     // t_vk
//         let t_start = Instant::now();
//     let t_vk = hash_pepper(&g_x, &salt_t, &p, 100_000);
//         let t_fin = Instant::now();
//         log!("t_time: {:?}", t_fin.duration_since(t_start));

//     // sig
//         let sig_start = Instant::now();
//     let m_sigma = [message, &p, &salt_t, &g_x].concat();
//     let signature = sign(&sk, 
//                         &m_sigma
//                     );
//         let sig_fin = Instant::now();
//         log!("sig_time: {:?}", sig_fin.duration_since(sig_start));
//     let proof = [&signature[..], &t_vk[..], &salt_t[..]].concat();
//         log!("---PROVE FINISH---");
//     proof
// }

pub fn random_password() -> Vec<u8> {
    let mut bytes : Vec<u8> = [0u8;10].to_vec();
    rand_bytes(&mut bytes).unwrap();
    bytes.to_vec()
}

pub fn random_data() -> Vec<u8> {
    let mut bytes : Vec<u8> = [0u8;64].to_vec();
    rand_bytes(&mut bytes).unwrap();
    bytes.to_vec()
}

pub fn random_pp() -> Vec<u8> {
    let mut bytes : Vec<u8> = [0u8;16].to_vec();
    rand_bytes(&mut bytes).unwrap();
    bytes.to_vec()
}

pub fn dummy_gen() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (random_password(), random_pp(), random_data())
}