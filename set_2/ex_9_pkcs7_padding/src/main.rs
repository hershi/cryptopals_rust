fn pad_block(mut input: Vec<u8>, block_size: u8) -> Vec<u8> {
    let block_size: usize = block_size as usize;
    let last_block_size = input.len() % block_size;
    let padding_needed = block_size - last_block_size;
    input.resize(input.len() + padding_needed, padding_needed as u8);
    input
}

fn format_result(input: &[u8], original_size: usize) -> String {
    input.iter()
        .enumerate()
        .map(|(i,x)|
             if i < original_size {
                 format!("{}", *x as char)
             } else {
                 format!("\\x{:02X}", x)})
        .collect::<String>()
}

fn main() {
    let input = "YELLOW SUBMARINE".as_bytes();
    let result =
        pad_block(input.to_vec(),
        20);

    println!("Result: {}", format_result(&result, input.len()));
}
