use std::collections::HashMap;

fn parse_key_values(input: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for kv_str in input.split('&') {
        let parts = kv_str.split('=').collect::<Vec<_>>();
        if parts.len() != 2 { continue; }
        map.insert(parts[0].to_string(), parts[1].to_string());
    }

    map
}


fn main() {
    println!("Map: {:?}", parse_key_values(&"foo=bar&baz=qux&zap=zazzle"));
}
