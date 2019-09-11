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

fn to_key_value_string(kvs: &HashMap<String, String>) -> String {
    kvs.iter()
        .map(|(k,v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

fn sanitize(email: &str) -> String {
    email.to_string()
}

fn profile_for(email: &str) -> String {
    let mut kvs = HashMap::new();
    kvs.insert("email".to_string(), sanitize(email));
    kvs.insert("uid".to_string(), "10".to_string());
    kvs.insert("role".to_string(), "user".to_string());

    to_key_value_string(&kvs)
}

fn main() {
    let input = "foo=bar&baz=qux&zap=zazzle";
    let map = parse_key_values(&input);
    println!("Map: {:?}", map);
    println!("As string: {}", to_key_value_string(&map));

    let email = "email=hello@world.com&a=b";
    println!("profile_for(\"{}\"): {}", email, profile_for(&email));
}
