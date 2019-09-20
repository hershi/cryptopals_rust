fn validate_padding(input: &[u8], block_size: usize) -> Result<(), &str> {
    if input.len() == 0 {
        return Err("bad padding - empty input");
    }

    let last_byte = *input.last().unwrap();
    if last_byte as usize > block_size {
        return Err("bad padding - last byte too big");
    }

    // Last byte is less than block size. Let's see if all the `last_byte` bytes
    // have that value
    if input.iter()
            .skip(block_size - last_byte as usize)
            .any(|&b| b != last_byte) {
        return Err("bad padding - some bytes with wrong value");
    }

    Ok(())
}

fn main() {
    let mut input = "ICE ICE BABY".as_bytes().to_vec();
    input.append(&mut vec![4,4,4,4]);
    println!("validate_padding: {:?}", validate_padding(&input, 16));
}
