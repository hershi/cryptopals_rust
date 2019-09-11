use std::collections::HashMap;

fn parse_key_values(input: &str) -> HashMap<&str, &str> {
    let mut map = HashMap::new();
    for kv_str in input.split('&') {
        let parts = kv_str.split('=').collect::<Vec<_>>();
        if parts.len() != 2 { continue; }
        map.insert(parts[0], parts[1]);
    }

    map
}

fn to_key_value_string(kvs: &HashMap<&str, &str>) -> String {
    kvs.iter()
        .map(|(k,v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

fn profile_for(email: &str) -> String {
    let mut kvs = HashMap::new();
    kvs.insert("email", email);
    kvs.insert("uid", "10");
    kvs.insert("role", "user");

    to_key_value_string(&kvs)
}

fn main() {
    let input = "foo=bar&baz=qux&zap=zazzle";
    let map = parse_key_values(&input);
    println!("Map: {:?}", map);
    println!("As string: {}", to_key_value_string(&map));

    let email = "hello@world.com";
    println!("profile_for(\"{}\"): {}", email, profile_for(&email));
}
