#![feature(rustc_private)]
extern crate crypto;
extern crate serialize;
extern crate base64;

use base64::{encode_mode, Base64Mode};
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use std::time::{UNIX_EPOCH, SystemTime, Duration};

static UNRESERVED: [&'static str; 256] =
    ["%00", "%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08", "%09", "%0A", "%0B", "%0C",
     "%0D", "%0E", "%0F", "%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17", "%18", "%19",
     "%1A", "%1B", "%1C", "%1D", "%1E", "%1F", "%20", "%21", "%22", "%23", "%24", "%25", "%26",
     "%27", "%28", "%29", "%2A", "%2B", "%2C", "-", ".", "%2F", "0", "1", "2", "3", "4", "5", "6",
     "7", "8", "9", "%3A", "%3B", "%3C", "%3D", "%3E", "%3F", "%40", "A", "B", "C", "D", "E", "F",
     "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X",
     "Y", "Z", "%5B", "%5C", "%5D", "%5E", "_", "%60", "a", "b", "c", "d", "e", "f", "g", "h",
     "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
     "%7B", "%7C", "%7D", "~", "%7F", "%80", "%81", "%82", "%83", "%84", "%85", "%86", "%87",
     "%88", "%89", "%8A", "%8B", "%8C", "%8D", "%8E", "%8F", "%90", "%91", "%92", "%93", "%94",
     "%95", "%96", "%97", "%98", "%99", "%9A", "%9B", "%9C", "%9D", "%9E", "%9F", "%A0", "%A1",
     "%A2", "%A3", "%A4", "%A5", "%A6", "%A7", "%A8", "%A9", "%AA", "%AB", "%AC", "%AD", "%AE",
     "%AF", "%B0", "%B1", "%B2", "%B3", "%B4", "%B5", "%B6", "%B7", "%B8", "%B9", "%BA", "%BB",
     "%BC", "%BD", "%BE", "%BF", "%C0", "%C1", "%C2", "%C3", "%C4", "%C5", "%C6", "%C7", "%C8",
     "%C9", "%CA", "%CB", "%CC", "%CD", "%CE", "%CF", "%D0", "%D1", "%D2", "%D3", "%D4", "%D5",
     "%D6", "%D7", "%D8", "%D9", "%DA", "%DB", "%DC", "%DD", "%DE", "%DF", "%E0", "%E1", "%E2",
     "%E3", "%E4", "%E5", "%E6", "%E7", "%E8", "%E9", "%EA", "%EB", "%EC", "%ED", "%EE", "%EF",
     "%F0", "%F1", "%F2", "%F3", "%F4", "%F5", "%F6", "%F7", "%F8", "%F9", "%FA", "%FB", "%FC",
     "%FD", "%FE", "%FF"];

static RESERVED: [&'static str; 256] =
    ["%00", "%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08", "%09", "%0A", "%0B", "%0C",
     "%0D", "%0E", "%0F", "%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17", "%18", "%19",
     "%1A", "%1B", "%1C", "%1D", "%1E", "%1F", "%20", "!", "%22", "#", "$", "%25", "&", "'", "(",
     ")", "*", "+", ",", "-", ".", "/", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":",
     ";", "%3C", "=", "%3E", "?", "@", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L",
     "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "[", "%5C", "]", "%5E",
     "_", "%60", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p",
     "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "%7B", "%7C", "%7D", "~", "%7F", "%80",
     "%81", "%82", "%83", "%84", "%85", "%86", "%87", "%88", "%89", "%8A", "%8B", "%8C", "%8D",
     "%8E", "%8F", "%90", "%91", "%92", "%93", "%94", "%95", "%96", "%97", "%98", "%99", "%9A",
     "%9B", "%9C", "%9D", "%9E", "%9F", "%A0", "%A1", "%A2", "%A3", "%A4", "%A5", "%A6", "%A7",
     "%A8", "%A9", "%AA", "%AB", "%AC", "%AD", "%AE", "%AF", "%B0", "%B1", "%B2", "%B3", "%B4",
     "%B5", "%B6", "%B7", "%B8", "%B9", "%BA", "%BB", "%BC", "%BD", "%BE", "%BF", "%C0", "%C1",
     "%C2", "%C3", "%C4", "%C5", "%C6", "%C7", "%C8", "%C9", "%CA", "%CB", "%CC", "%CD", "%CE",
     "%CF", "%D0", "%D1", "%D2", "%D3", "%D4", "%D5", "%D6", "%D7", "%D8", "%D9", "%DA", "%DB",
     "%DC", "%DD", "%DE", "%DF", "%E0", "%E1", "%E2", "%E3", "%E4", "%E5", "%E6", "%E7", "%E8",
     "%E9", "%EA", "%EB", "%EC", "%ED", "%EE", "%EF", "%F0", "%F1", "%F2", "%F3", "%F4", "%F5",
     "%F6", "%F7", "%F8", "%F9", "%FA", "%FB", "%FC", "%FD", "%FE", "%FF"];

pub fn encode_unreserved(s: &str) -> String {
    let mut res = String::new();
    for &byte in s.as_bytes() {
        res.push_str(UNRESERVED[byte as usize]);
    }
    res
}

pub fn encode_reserved(s: &str) -> String {
    let mut res = String::new();
    for &byte in s.as_bytes() {
        res.push_str(RESERVED[byte as usize]);
    }
    res
    //    // Correct any percent-encoded triplets whose percent signs were reencoded
    //    Regex::new("%25(?P<hex>[0-9a-fA-F][0-9a-fA-F])")
    //        .unwrap()
    //        .replace_all(&res, "%$hex")
}

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
    hmac.reset();
    String::from(ak) + ":" + &token
}

fn download_token(url: String, expire: u64) -> String {
    let (ak, sk) = ("MY_ACCESS_KEY", "MY_SECRET_KEY");
    let s_now = SystemTime::now();
    let d_exprie = Duration::new(expire, 0);
    let s_exprie = s_now + d_exprie;
    let r_exprie: String = s_exprie.duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
    let t_uri = encode_reserved(&url) + "?e=" + &r_exprie;
    let token = manage_token(sk, ak, &t_uri);

    t_uri + "&token=" + &token
}

fn main() {
    let mt = manage_token("MY_SECRET_KEY",
                          "MY_ACCESS_KEY",
                          "/move/bmV3ZG9jczpmaW5kX21hbi50eHQ=/bmV3ZG9jczpmaW5kLm1hbi50eHQ=\n");
    println!("{}", mt);
    let s_url = download_token("http://78re52.com1.z0.glb.clouddn.com/resource/flower.jpg"
                                   .to_string(),
                               3600);
    println!("{}", s_url)

}
