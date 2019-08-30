pub fn hex_decode(input: &str) -> Vec<u8> {
    input.chars()
        .zip(input.chars().skip(1))
        .step_by(2)
        .map(|(c1,c2)| {
            let mut pair = String::with_capacity(2);
            pair.push(c1);
            pair.push(c2);
            pair})
        .map(|hex_byte_str| u8::from_str_radix(&hex_byte_str, 16).unwrap())
        .collect::<Vec<u8>>()
}

pub fn hex_encode(input: &Vec<u8>) -> String {
    input.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}
