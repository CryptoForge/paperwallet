
use sha2::{Digest, Sha256};
use bip39::{Language, Mnemonic};
use crate::extended_key::{ExtendedPrivKey, KeyIndex};
use base58::{ToBase58};

/// Sha256(Sha256(value))
pub fn double_sha256(payload: &[u8]) -> Vec<u8> {
    let h1 = Sha256::digest(&payload);
    let h2 = Sha256::digest(&h1);
    h2.to_vec()
}

/// A trait for converting a [u8] to base58 encoded string.
pub trait ToBase58Check {
    /// Converts a value of `self` to a base58 value, returning the owned string.
    /// The version is a coin-specific prefix that is added.
    /// The suffix is any bytes that we want to add at the end (like the "iscompressed" flag for
    /// Secret key encoding)
    fn to_base58check(&self, version: &[u8], suffix: &[u8]) -> String;
}

impl ToBase58Check for [u8] {
    fn to_base58check(&self, version: &[u8], suffix: &[u8]) -> String {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(version);
        payload.extend_from_slice(self);
        payload.extend_from_slice(suffix);

        let checksum = double_sha256(&payload);
        payload.append(&mut checksum[..4].to_vec());
        payload.to_base58()
    }
}

pub fn address_from_prefix_sk(prefix: &[u8; 2], sk: &secp256k1::SecretKey) -> String {
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        // Encode into t address
        let mut hash160 = ripemd160::Ripemd160::new();
        hash160.input(Sha256::digest(&pk.serialize()[..].to_vec()));

        hash160.result().to_base58check(prefix, &[])
    }

pub fn encoded_sk(prefix: &[u8; 1], sk: &secp256k1::SecretKey) -> String {
        sk[..].to_base58check(prefix, &[0x01])
    }

pub fn get_taddress(seed: &[u8], index: u32, coin_type: u32, nobip39: bool) -> (String, String) {
        let bip39_seed = bip39::Seed::new(&Mnemonic::from_entropy(&seed, Language::English).unwrap(), "");


        let ext_t_key = ExtendedPrivKey::with_seed(bip39_seed.as_bytes()).unwrap();
        let sk = ext_t_key
            .derive_private_key(KeyIndex::hardened_from_normalize_index(44).unwrap()).unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(coin_type).unwrap()).unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(0).unwrap()).unwrap()
            .derive_private_key(KeyIndex::Normal(0)).unwrap()
            .derive_private_key(KeyIndex::Normal(index)).unwrap()
            .private_key;

        (address_from_prefix_sk(&[0x1C,0xB8], &sk), encoded_sk(&[0x80], &sk))
    }
