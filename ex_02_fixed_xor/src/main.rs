fn hex_decode(input: &str) -> Vec<u8> {
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

fn xor(input: &Vec<u8>, output: &Vec<u8>) -> Vec<u8> {
    input.iter()
        .zip(output.iter())
        .map(|(rhs, lhs)| rhs ^ lhs)
        .collect()
}

fn to_hex(input: &Vec<u8>) -> String {
    input.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join("")
}

fn main() {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";
    println!("{} ^ {} == {}", input1, input2,
             to_hex(
                 &xor(
                     &hex_decode(&input1),
                     &hex_decode(&input2))
            ));
}
