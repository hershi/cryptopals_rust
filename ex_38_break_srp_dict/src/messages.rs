extern crate num_bigint as bigint;

use serde::{Serialize, Deserialize};
use bigint::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientRegistration {
    pub email: String,
    pub salt: i32,
    pub verifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientHello {
    pub email: String,
    pub public_key: String,
}

impl ClientHello {
    pub fn new(email: &str, public_key: &BigUint) -> ClientHello {
        ClientHello{
            email: email.to_string(),
            public_key: biguint_to_string(&public_key),}
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn deserialize(msg: &str) -> ClientHello {
        serde_json::from_str::<ClientHello>(msg).unwrap()
    }
}

pub struct UserRecord {
    pub salt: i32,
    pub verifier: BigUint,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerChallenge {
    pub salt: i32,
    pub public_key: String,
    pub u: u128,
}

impl ServerChallenge {
    pub fn new(salt: i32, public_key: &BigUint, u: u128) -> ServerChallenge {
        ServerChallenge{
            salt,
            public_key: biguint_to_string(&public_key),
            u,
        }
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn deserialize(msg: &str) -> ServerChallenge {
        serde_json::from_str::<ServerChallenge>(msg).unwrap()
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct ClientResponse {
    pub resp: Vec<u8>,
}

impl ClientResponse {
    pub fn new(resp: Vec<u8>) -> ClientResponse {
        ClientResponse{resp}
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn deserialize(msg: &str) -> ClientResponse {
        serde_json::from_str::<ClientResponse>(msg).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerOk {
    pub ok: bool,
}

impl ServerOk {
    pub fn new(ok: bool) -> ServerOk {
        ServerOk{ok}
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn deserialize(msg: &str) -> ServerOk {
        serde_json::from_str::<ServerOk>(msg).unwrap()
    }
}

pub fn biguint_to_string(x: &BigUint) -> String {
    x.to_str_radix(16)
}

pub fn biguint_from_string(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).unwrap()
}

