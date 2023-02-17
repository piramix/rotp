use std::env;
use url::Url;
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::Mac;
use base32::Alphabet::RFC4648;
type HmacSha1 = hmac::Hmac<sha1::Sha1>;

fn totp(secret: &str, time_step: u64) -> Vec<u8> {
    let bsecret = base32::decode(RFC4648 { padding: false }, &secret).unwrap();
    let timestamp = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .unwrap()
         .as_secs();
    let time_step_count = timestamp / time_step;
    let mut digest = HmacSha1::new_from_slice(&bsecret).unwrap();
    digest.update(&time_step_count.to_be_bytes());
    return digest.finalize().into_bytes().to_vec();
}

fn totp_code(digest: &[u8], digits: usize) -> String {
    let offset: usize = (digest[digest.len()-1] & 0xf).into();
    let code = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset+1] as u32) << 16)
        | ((digest[offset+2] as u32) << 8)
        | digest[offset+3] as u32;

    let mut result = String::new();
    let mut code_result = code % (10_u32.pow(digits.try_into().unwrap()));

    while code_result > 0 {
        let c = (code_result % 10) as u8;
        result.insert(0, (b'0' + c) as char);
        code_result /= 10;
    }
    while result.len() < digits {
        result.insert(0, '0');
    }
    result
}

fn decode_otpauth_url(url_string: &str) -> Option<(String,String)> {
    let url = Url::parse(url_string).ok()?;
    if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
        return None;
    }
    let account_name = url.path()[1..].to_owned();
    let query = url.query()?;
    let secret = url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == "secret")?
        .1;
    return Some((account_name.to_string(),secret.to_string()));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let url = match args.get(1) {
        Some(s) => s,
        None => {
            eprintln!("Usage: rotp <url>");
            return;
        }
    };
    let result = decode_otpauth_url(url);
    if result.is_none() {
        eprintln!("Wrong otpauth url");
        return
    } else {
        let (account_name, secret) = result.unwrap();
        let digest = totp(&secret, 30);
        let code = totp_code(&digest, 6);
        println!("Account name: {}", account_name);
        println!("Secret key: {}", secret);
        println!("OTP code: {}", code);
    }
}