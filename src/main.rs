use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tiny_keccak::{Hasher, Keccak};

#[derive(Deserialize)]
#[serde(untagged)]
enum AddressItem {
    Str(String),
    Obj { address: String },
}

#[derive(Serialize)]
struct FoundResult {
    address: String,
    private_key: String,
}

fn parse_addr(s: &str) -> Option<[u8; 20]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

fn load_addresses<P: AsRef<Path>>(path: P) -> HashSet<[u8; 20]> {
    let data = fs::read_to_string(path).expect("failed to read addresses.json");
    let items: Vec<AddressItem> = serde_json::from_str(&data).expect("invalid JSON");
    items
        .into_iter()
        .filter_map(|it| {
            let s = match &it {
                AddressItem::Str(s) => s.as_str(),
                AddressItem::Obj { address } => address.as_str(),
            };
            parse_addr(s)
        })
        .collect()
}

#[inline(always)]
fn address_from_secret(sk: &SecretKey, out: &mut [u8; 20]) {
    let pk = secp256k1::PublicKey::from_secret_key_global(sk);
    let pub_bytes = pk.serialize_uncompressed();
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(&pub_bytes[1..]);
    keccak.finalize(&mut hash);
    out.copy_from_slice(&hash[12..]);
}

fn main() {
    let addresses = Arc::new(load_addresses("data/addresses.json"));
    println!("loaded {} addresses", addresses.len());

    let found = Arc::new(AtomicBool::new(false));

    rayon::scope(|s| {
        for worker_id in 0..num_cpus::get() - 1 {
            let addresses = Arc::clone(&addresses);
            let found = Arc::clone(&found);

            s.spawn(move |_| {
                let mut local_count: u64 = 0;
                let mut rng = ChaCha8Rng::from_os_rng();

                let mut addr_buf = [0u8; 20];
                while !found.load(Ordering::Relaxed) {
                    let sk = SecretKey::new(&mut rng);
                    address_from_secret(&sk, &mut addr_buf);
                    local_count += 1;

                    if local_count % 10_000_000 == 0 {
                        println!("worker {} checked {}", worker_id, local_count);
                    }

                    if addresses.contains(&addr_buf) {
                        found.store(true, Ordering::Relaxed);
                        let address = format!("0x{}", hex::encode(addr_buf));
                        let private_key = format!("0x{}", hex::encode(sk.secret_bytes()));
                        println!(
                            "worker {} FOUND after {} checks: {}",
                            worker_id, local_count, address
                        );
                        println!("private key (hex): {}", private_key);
                        let result = FoundResult { address, private_key };
                        let j = serde_json::to_string_pretty(&result).unwrap();
                        fs::File::create("data/v.json")
                            .and_then(|mut f| f.write_all(j.as_bytes()))
                            .expect("failed to write v.json");
                        break;
                    }
                }
            });
        }
    });
}