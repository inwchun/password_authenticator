
use pkcs11::{Ctx, errors::Error};
use pkcs11::types::*;
use chrono::{DateTime, Utc};
use cookie_factory;
use crate::prompt;

pub struct KeyStore {
    ctx: Ctx,
    session: CK_SESSION_HANDLE,
}

impl Drop for KeyStore {
    fn drop(&mut self) {
        self.ctx.close_session(self.session).unwrap()
    }
}

fn match_label(pattern: &str, label: &[u8; 32]) -> bool {
    match std::str::from_utf8(label) {
        Ok(label) => label.trim() == pattern.trim(),
        Err(_) => false
    }
}

fn find_token(ctx: &Ctx, label: &str) -> Result<Vec<CK_SLOT_ID>, Error> {
    let mut result = vec!();
    for slot_id in ctx.get_slot_list(true)? {
        let info = ctx.get_token_info(slot_id)?;
        if match_label(label, &info.label) {
            result.push(slot_id);
        }
    }
    Ok(result)
}

fn login(ctx: &Ctx, slot_id: CK_SLOT_ID,
         pin_file: &Option<String>) -> Result<CK_SESSION_HANDLE, Error> {
    let info = ctx.get_token_info(slot_id)?;
    let s = ctx.open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             None, None)?;
    let need_pin = info.flags & CKF_PROTECTED_AUTHENTICATION_PATH == 0;
    let pin = match (need_pin, pin_file) {
        (false, _) => secstr::SecStr::new(vec!()),
        (true, None) => {
            let prompt = format!(
                "Please insert the User PIN for the token with\nlabel: {}",
                String::from_utf8_lossy(&info.label));
            prompt::read_pin(&prompt).expect("Can't read PIN")
        },
        (true, Some(filename)) => read_pin_file(filename)
            .expect(&format!("Can't read PIN from file {}", filename)),
    };
    ctx.login(s, CKU_USER, match need_pin {
        true => Some(std::str::from_utf8(pin.unsecure()).unwrap()),
        false => None
    })?;
    Ok(s)
}

fn read_pin_file(file_name: &str) -> std::io::Result<secstr::SecStr> {
    fn erase(v: &mut Vec<u8>) { v.iter_mut().map(|x| *x = 0).count(); }
    let mut output = std::process::Command::new("gpg")
        .arg("--decrypt").arg(file_name)
        .output()?;
    if output.status.success() {
        let stdout = &mut output.stdout;
        let v = stdout[..stdout.len()-1].to_vec();
        erase(stdout);
        Ok(secstr::SecStr::new(v))
    } else {
        erase(&mut output.stdout);
        panic!("gpg failed: {}",
               String::from_utf8_lossy(&output.stderr))
    }
}

pub fn open_token (module: &std::path::Path, label: &str,
                   pin_file: &Option<String>)
                   -> Result<KeyStore, Error> {
    let ctx = Ctx::new_and_initialize(module)?;
    let slot_ids = find_token(&ctx, label)?;
    let slot_id = match slot_ids.len() {
        1 => slot_ids[0],
        l => return Err(Error::Module(match l {
            0 => "No token with matching label found",
            _ => "Multiple tokens with matching label found",
        })),
    };
    let s = login(&ctx, slot_id, pin_file)?;
    let token = KeyStore{ ctx: ctx, session: s};
    match token.find_secret_key()? {
        None => {
            log!("Generating secret key...");
            token.create_secret_key()?
        },
        _ => log!("Found secret key."),
    };
    match token.find_token_counter()? {
        None => {
            log!("Generating token counter...");
            token.create_token_counter(0)?
        },
        _ => log!("Found token counter. ({})",
                  token.increment_token_counter()?),
    };
    Ok(token)
}

// OID: 1.2.840.10045.3.1.7
const SECP256R1_OID: &[u64] = &[1,2,840,10045,3,1,7];

fn curve_oid (name: &str) -> &'static [u8] {
    // DER encoding of OID: 1.2.840.10045.3.1.7
    const OID:&[u8] =
        &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    match name {
        "secp256r1" => /*"1.2.840.10045.3.1.7".as_bytes() */ OID,
        _ => panic!("Uknown curve: {}", name)
    }
}

// fn der_encode_oid(oid: &'static [u64]) -> Vec<u8> {
//     let (buf, _pos) = cookie_factory::gen(
//         x509::der::write::der_oid(oid),
//         Vec::<u8>::new()).unwrap();
//     buf
// }

// See Section Octet-String-to-Elliptic-Curve-Point Conversion
// in http://www.secg.org/sec1-v2.pdf.
fn ec_point_x_y (point: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert!(point[0] == 0x04, "not a DER octed string tag");
    assert!(point[1] == 65, "invalid length");
    assert!(point[2] == 0x04, "point not in uncompressed format");
    let len = point.len();
    assert!(len == 67);
    assert!((len - 3) % 2 == 0);
    let l = (len - 3) / 2;
    assert!(l == 32);
    let (x, y) = (point[3..3+l].to_vec(), point[3+l..].to_vec());
    (x, y)
}

// Set all elements to 0
fn zero(data: &mut [u8]) {
    for i in 0..data.len() {
        data[i] = 0;
    }
}

fn with_vec<T, F>(data: &[u8], f: F) -> T
    where F: FnOnce(&Vec<u8>) -> T {
    let mut tmp = data.to_vec();
    let result = f(&tmp);
    zero(&mut tmp);
    result
}

fn der_encode_signature (points: &[u8]) -> Vec<u8> {
    assert!(points.len() == 64);
    let (r, s) = (&points[..32], &points[32..]);
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

pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = rust_crypto::sha2::Sha256::new();
    use crate::rust_crypto::digest::Digest;
    hasher.input(data);
    let mut result = vec!(0; hasher.output_bytes());
    hasher.result(&mut result);
    result
}

// shorthand for mechanism without paramaters.
fn mechanism(mechanism: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: mechanism,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    }
}

const A: fn(CK_ATTRIBUTE_TYPE) -> CK_ATTRIBUTE = CK_ATTRIBUTE::new;

const SECRET_KEY_LABEL: &str = "softfido-secret-key";
const TOKEN_COUNTER_LABEL: &str = "softfido-token-counter";

impl KeyStore {

    fn find_secret_key(&self) -> Result<Option<CK_OBJECT_HANDLE>, Error> {
        let (ctx, s) = (&self.ctx, self.session);
        ctx.find_objects_init(
            s,
            &vec![A(CKA_LABEL).with_string(&SECRET_KEY_LABEL.to_string()),
                  A(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY)],)?;
        let r = ctx.find_objects(s, 2)?;
        ctx.find_objects_final(s)?;
        match r.len() {
            0 => Ok(None),
            1 => Ok(Some(r[0])),
            _ => Err(Error::Module("Found multiple secret keys"))
        }
    }

    fn find_token_counter(&self) -> Result<Option<CK_OBJECT_HANDLE>, Error> {
        let (ctx, s) = (&self.ctx, self.session);
        ctx.find_objects_init(
            s,
            &vec![A(CKA_LABEL).with_string(&TOKEN_COUNTER_LABEL.to_string()),
                  A(CKA_CLASS).with_ck_ulong(&CKO_DATA)],)?;
        let r = ctx.find_objects(s, 2)?;
        ctx.find_objects_final(s)?;
        match r.len() {
            0 => Ok(None),
            1 => Ok(Some(r[0])),
            _ => Err(Error::Module("Found multiple token counters"))
        }
    }

    fn create_secret_key(&self) -> Result<(), Error> {
        self.ctx.generate_key(
            self.session, &mechanism(CKM_AES_KEY_GEN),
            &vec![A(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY),
                  A(CKA_KEY_TYPE).with_ck_ulong(&CKK_AES),
                  A(CKA_VALUE_LEN).with_ck_ulong(&32),
                  A(CKA_LABEL).with_string(&SECRET_KEY_LABEL.to_string()),
                  A(CKA_TOKEN).with_bool(&CK_TRUE),
                  A(CKA_SENSITIVE).with_bool(&CK_TRUE),
                  A(CKA_EXTRACTABLE).with_bool(&CK_FALSE),
                  A(CKA_WRAP).with_bool(&CK_TRUE),
                  A(CKA_UNWRAP).with_bool(&CK_TRUE),
                  A(CKA_ENCRYPT).with_bool(&CK_TRUE),
                  A(CKA_DECRYPT).with_bool(&CK_TRUE),
            ],)?;
        assert!(self.find_secret_key().unwrap().is_some());
        Ok(())
    }
    
    fn create_token_counter(&self, value:u32) -> Result<(), Error> {
        self.ctx.create_object(
            self.session, 
            &vec![A(CKA_CLASS).with_ck_ulong(&CKO_DATA),
                  A(CKA_TOKEN).with_bool(&CK_TRUE),
                  A(CKA_LABEL).with_string(&TOKEN_COUNTER_LABEL.to_string()),
                  A(CKA_DESTROYABLE).with_bool(&CK_TRUE),
                  A(CKA_VALUE).with_bytes(&value.to_be_bytes()),
            ],)?;
        assert!(self.find_token_counter().unwrap().is_some());
        Ok(())
    }

    pub fn increment_token_counter(&self) -> Result<u32, Error> {
        let (ctx, s) = (&self.ctx, self.session);
        let counter = self.find_token_counter().unwrap().unwrap();
        #[allow(unused_mut)]
        let mut bytes = [0u8;4];
        let mut template = vec![A(CKA_VALUE).with_bytes(&bytes)];
        let v = match ctx.get_attribute_value(s, counter, &mut template) {
            Ok((CKR_OK, _)) => u32::from_be_bytes(bytes),
            Ok((err,_)) => return Err(Error::Pkcs11(err)),
            Err(err) => return Err(err),
        };
        ctx.destroy_object(s, counter)?;
        self.create_token_counter(v+1)?; 
        Ok(v)
    }

    fn get_bytes_attribute(&self, key: CK_OBJECT_HANDLE,
                           attr: CK_ATTRIBUTE_TYPE)
                           -> Result<Vec<u8>, Error> {
        let (ctx, s) = (&self.ctx, self.session);
        let mut template = vec![CK_ATTRIBUTE::new(attr)];
        match ctx.get_attribute_value(s, key, &mut template) {
            Ok((CKR_OK, _)) => (),
            Ok((CKR_BUFFER_TOO_SMALL, _)) => (),
            Ok((err,_)) => return Err(Error::Pkcs11(err)),
            Err(err) => return Err(err),
        }
        let mut bytes = vec!(0; template[0].ulValueLen);
        template[0].set_bytes(&mut bytes);
        match ctx.get_attribute_value(s, key, &mut template) {
            Ok((CKR_OK, _)) => Ok(bytes),
            Ok((err,_)) => Err(Error::Pkcs11(err)),
            Err(err) => Err(err),
        }
    }

    // Return the private and public keys.
    // The wrapped private key is also the credentialId.
    // The public key is an (x, y) point of an elliptic curve.
    pub fn generate_key_pair(&self) -> Result<(Vec<u8>, (Vec<u8>, Vec<u8>)),
                                              Error> {
        let (ctx, s) = (&self.ctx, self.session);
        let (pub_key, priv_key) = ctx.generate_key_pair(
            s, &mechanism(CKM_EC_KEY_PAIR_GEN),
            &vec![A(CKA_KEY_TYPE).with_ck_ulong(&CKK_EC),
                  A(CKA_TOKEN).with_bool(&CK_FALSE),
                  A(CKA_EC_PARAMS).with_bytes(curve_oid("secp256r1")),
            ],
            &vec![A(CKA_TOKEN).with_bool(&CK_FALSE),
                  A(CKA_EXTRACTABLE).with_bool(&CK_TRUE),
            ])?;
        let wrapping_key = self.find_secret_key()?.unwrap();
        let wrapped_key = ctx.wrap_key(s, &mechanism(CKM_AES_KEY_WRAP_PAD),
                                       wrapping_key, priv_key)?;
        Ok((wrapped_key,
            ec_point_x_y(&self.get_bytes_attribute(pub_key, CKA_EC_POINT)?)))
    }

    pub fn is_valid_id(&self, key: &[u8]) -> bool {
        let wrapping_key = self.find_secret_key().unwrap().unwrap();
        self.ctx.unwrap_key(
            self.session, &mechanism(CKM_AES_KEY_WRAP_PAD),
            wrapping_key, &key.to_vec(),
            &vec![A(CKA_CLASS).with_ck_ulong(&CKO_PRIVATE_KEY),
                  A(CKA_KEY_TYPE).with_ck_ulong(&CKK_EC),
                  A(CKA_TOKEN).with_bool(&CK_FALSE),
            ]).is_ok()
    }

    pub fn sha256_hash(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let (ctx, s) = (&self.ctx, self.session);
        ctx.digest_init(s, &mechanism(CKM_SHA256))?;
        with_vec(data, |data| ctx.digest(s, data))
    }
    
    pub fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        let (ctx, s) = (&self.ctx, self.session);
        let hash = self.sha256_hash(&data)?;
        assert!(hash == sha256_hash(data));
        let wrapping_key = self.find_secret_key()?.unwrap();
        let private_key = ctx.unwrap_key(
            s, &mechanism(CKM_AES_KEY_WRAP_PAD),
            wrapping_key, &key.to_vec(),
            &vec![A(CKA_CLASS).with_ck_ulong(&CKO_PRIVATE_KEY),
                  A(CKA_KEY_TYPE).with_ck_ulong(&CKK_EC),
                  A(CKA_TOKEN).with_bool(&CK_FALSE),
            ])?;
        ctx.sign_init(s, &mechanism(CKM_ECDSA), private_key)?;
        let signature = ctx.sign(s, &hash)?;
        Ok(der_encode_signature(&signature))
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        println!("encrypt: data.len={}", data.len());
        let len = data.len();
        assert!(len <= 255);
        let d = [&[len as u8][..], data, &vec![0u8;31-len%32]].concat();
        let (ctx, s) = (&self.ctx, self.session);
        let key = self.find_secret_key()?.unwrap();
        ctx.encrypt_init(s, &mechanism(CKM_AES_ECB), key)?;
        ctx.encrypt(s, &d.to_vec())
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        println!("decrypt");
        if data.len()%32 != 0 || data.len() == 0 {
            return Err(Error::Module("data has invalid length"));
        }
        let (ctx, s) = (&self.ctx, self.session);
        let key = self.find_secret_key()?.unwrap();
        ctx.decrypt_init(s, &mechanism(CKM_AES_ECB), key)?;
        let d = ctx.decrypt(s, &data.to_vec())?;
        let len = d[0];
        if 1+len as usize > d.len() {
            return Err(Error::Module("invalid decrypted data"));
        }
        Ok(d[1..1+len as usize].to_vec())
    }

    
    pub fn create_certificate(&self, wrapped_priv_key: &[u8], pub_key: &[u8],
                              issuer: &str, subject: &str,
                              not_before: DateTime<Utc>, 
                              not_after: Option<DateTime<Utc>>) ->
        Result<Vec<u8>, Error> {
            let algo = AlgorithmIdentifier{ oid: SECP256R1_OID };
            let (tbs_cert, _pos) = cookie_factory::gen(
                x509::write::tbs_certificate(
                    &[0],
                    &algo,
                    issuer,
                    not_before, not_after,
                    subject,
                    &SubjectPublicKeyInfo{algorithm_id: &algo,
                                          public_key: pub_key}
                ),
                Vec::<u8>::new()).unwrap();
            let sig = self.sign(wrapped_priv_key, &tbs_cert)?;
            let (cert, _pos) = cookie_factory::gen(
                x509::write::certificate(&tbs_cert, &algo, &sig),
                Vec::new()).unwrap();
            Ok(cert)
        }
}

#[derive(Clone)]
struct AlgorithmIdentifier {
    oid: &'static [u64],
}

impl x509::AlgorithmIdentifier for AlgorithmIdentifier {
    type AlgorithmOid = &'static [u64];
    fn algorithm(&self) -> &'static [u64] { self.oid }
    fn parameters<W: std::io::Write>(&self, w: cookie_factory::WriteContext<W>)
                                     ->  cookie_factory::GenResult<W> {
        Ok(w)
    }
}

struct SubjectPublicKeyInfo<'a> {
    algorithm_id: &'a AlgorithmIdentifier,
    public_key: &'a [u8],
}

impl<'a> x509::SubjectPublicKeyInfo for SubjectPublicKeyInfo<'a> {
    type AlgorithmId = AlgorithmIdentifier;
    type SubjectPublicKey = &'a [u8];
    fn algorithm_id (&self) -> AlgorithmIdentifier {
        self.algorithm_id.clone() }
    fn public_key (&self) -> &'a [u8] { self.public_key }
}
