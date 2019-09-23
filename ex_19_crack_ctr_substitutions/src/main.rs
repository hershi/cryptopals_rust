#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use utils::*;
use utils::encoding::*;
use utils::encryption::*;
use data_encoding::BASE64;

//const KEY_SIZE : usize = 16;

lazy_static! {
    //pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
    pub static ref KEY: Vec<u8> = vec![186, 253, 209, 51, 233, 155, 147, 181, 252, 203, 168, 39, 228, 14, 101, 24];
    pub static ref INPUT_STRINGS : Vec<&'static str> = vec![
        "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    ];
}

fn encrypt_inputs() -> Vec<Vec<u8>> {
    INPUT_STRINGS.iter()
        .map(|input| BASE64.decode(input.as_bytes()).unwrap())
        .map(|input| ctr_encrypt(&input, &KEY, 0))
        .collect()
}

fn slice_inputs(
    inputs: &Vec<Vec<u8>>,
    start: usize,
    count: usize) -> Vec<Vec<u8>> {
    inputs.iter()
        .map(|input| input
             .iter()
             .skip(start)
             .take(count)
             .cloned()
             .collect::<Vec<u8>>())
        .filter(|slice| slice.len() > 0)
        .collect()
}

fn build_counts_map(inputs: Vec<Vec<u8>>) -> HashMap<Vec<u8>, usize> {
    inputs.into_iter()
        .fold(HashMap::new(),
        |mut acc, key| {
            *acc.entry(key).or_insert(0) += 1;
            acc })
}

fn slice_and_count(
        inputs: &Vec<Vec<u8>>,
        start: usize,
        count: usize) -> HashMap<Vec<u8>, usize> {
    let slices = slice_inputs(inputs, start, count);
    build_counts_map(slices)
}

fn print_map(map: &HashMap<Vec<u8>, usize>) {
    let mut vec = map.iter()
        .map(|(k,v)| (k.clone(), *v))
        .collect::<Vec<(Vec<u8>, usize)>>();

    vec.sort_by_key(|item| item.1);

    for (k, v) in vec {
        println!("{:?} : {}", k, v);
    }
}

fn seems_legit(map: &HashMap<Vec<u8>, usize>) -> bool {
    map.keys()
        .map(|k| k.iter().all(|b| b.is_ascii()))
        .all(|b| b)
}

fn main() {
    let encrypted_inputs = encrypt_inputs();
    for x in encrypted_inputs.iter() {
        println!("{:?}", x);
    }
    println!("");

    let x = slice_and_count(&encrypted_inputs, 0, 5);
    print_map(&x);

    // 4th
    //let mut ct = vec![132, 200, 221, 134, 245, 31, 128, 129, 129, 25, 135, 77, 177, 226, 224, 116, 100, 241, 51, 56, 204, 88, 35, 91, 80, 102];
    //let pt = b"Eighteenth-century";

    // 5th from last
    //let mut ct = vec![137, 196, 150, 206, 245, 21, 138, 195, 213, 25, 203, 93, 244, 254, 241, 114, 127, 239, 125, 53, 199, 13, 56, 87, 80, 104, 187, 139, 20, 70];
    //let pt = b"He, too, has resigned";

    // 3rd from last
    //let mut ct = vec![137, 196, 150, 206, 245, 21, 138, 195, 213, 25, 203, 93, 244, 238, 241, 100, 120, 168, 112, 56, 194, 67, 55, 91, 71, 104, 162, 132, 70, 90, 223, 114, 255, 111, 71, 148, 192, 224];
    //let pt = b"He, too, has been ";


    // 2nd
    //let mut ct = vec![130, 206, 215, 135, 239, 29, 197, 152, 156, 5, 194, 14, 162, 229, 226, 104, 114, 168, 117, 49, 192, 72, 35];
    //let pt = b"Coming with";

    // Last
    //let mut ct = vec![128, 129, 206, 139, 243, 8, 140, 141, 153, 20, 138, 76, 177, 237, 225, 117, 111, 168, 122, 35, 131, 79, 63, 76, 77, 102];
    //let pt = b"A terrible";

    // 7th
    //let mut ct = vec![142, 211, 154, 134, 224, 12, 128, 207, 153, 24, 196, 73, 177, 254, 241, 101, 54, 233, 100, 56, 202, 65, 53, 30, 66, 38, 175, 202, 21, 83, 223, 101];
    //let pt = b"Or have lingered awhile";

    //let mut ct = vec![137, 196, 150, 206, 245, 21, 138, 195, 213, 25, 203, 93, 244, 238, 241, 100, 120, 168, 112, 56, 194, 67, 55, 91, 71, 104, 162, 132, 70, 90, 223, 114, 255, 111, 71, 148, 192, 224];
    //let pt = b"He, too, has been changed";

    let mut ct = vec![137, 196, 150, 206, 245, 21, 138, 195, 213, 25, 203, 93, 244, 238, 241, 100, 120, 168, 112, 56, 194, 67, 55, 91, 71, 104, 162, 132, 70, 90, 223, 114, 255, 111, 71, 148, 192, 224];
    let pt = b"He, too, has been changed in his turn";

    ct.truncate(pt.len());
    let ks = xor(&ct, pt);

    let punctuation = b":;?!\"#$%&'*.,-".to_vec();
    let r = encrypted_inputs.iter()
        //.filter(|prefix| prefix.len() >= ks.len())
        //.inspect(|prefix| println!("{:?}", prefix))
        .map(|encrypted| encrypted.iter().take(ks.len()).cloned().collect::<Vec<u8>>())
        .map(|prefix| xor(&prefix, &ks))
        .inspect(|prefix| println!("{}", to_string(&prefix)))
        .map(|prefix| prefix.iter().all(
                |b| b.is_ascii_alphanumeric() || b.is_ascii_whitespace() || punctuation.contains(b)
            ))
        .all(|b| b);
    println!("Valid KS? {}", r);
}
