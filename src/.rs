#![feature(rustc_private)]
extern crate crypto;
extern crate serialize;
extern crate base64;

use base64::{encode_mode, Base64Mode};
// use serialize::hex::ToHex;
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use std::time::{UNIX_EPOCH, SystemTime, Instant, Duration};

fn str_vec(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn manage_token(sk: &str, ak: &str, msg: &str) -> String {
    let s_key: Vec<u8> = str_vec(sk);
    let a_msg: Vec<u8> = str_vec(msg);
    let mut hmac = Hmac::new(Sha1::new(), &s_key[..]);
    hmac.input(&a_msg[..]);
    let result = hmac.result();
    let token = encode_mode(result.code(), Base64Mode::UrlSafe);
    String::from(ak) + ":" + &token
}

fn download_token(url: String, expire: i64) -> String {
    "dddddhttps://github.com/servo/rust-url".to_string()
}

fn main() {
    let mt = manage_token("MY_SECRET_KEY",
                          "MY_ACCESS_KEY",
                          "/move/bmV3ZG9jczpmaW5kX21hbi50eHQ=/bmV3ZG9jczpmaW5kLm1hbi50eHQ=\n");
    println!("{}", mt);

    let stable_now = SystemTime::now();;
    println!("{:?}", stable_now);

    let temp = Duration::new(1, 0);
    let later = stable_now + temp;
    println!("{:?}", temp);
    let SystemTime { time_s: i64, time_ns: i64 } = stable_now;
    pritnln!("ddddddddddddddddddddddddddd");
    println!("kkkk:{:?}::::{:?}", time_s, timens);
    println!("s:{:?}", later);
}
