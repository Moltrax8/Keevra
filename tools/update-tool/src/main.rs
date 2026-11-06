//! Offline update-manifest tool (maintainer-only, never shipped).
//!
//! Usage (run on an OFFLINE machine holding the private key):
//!   update-tool gen-key <out-prefix>            # writes <out>.key (SECRET) + <out>.pub
//!   update-tool sign <manifest.json> --key <out.key> [--out <manifest.json.minisig>]
//!
//! The `.key` file is base64 32-byte seed — never commit it. The `.pub`
//! value is baked into `src-tauri/src/update_keys.rs`.
//!
//! Lives in `tools/` (its own crate) so the Tauri NSIS bundler only ever
//! sees the single app binary in `src-tauri`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey};
use std::{fs, path::PathBuf};

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  update-tool gen-key <out-prefix>");
    eprintln!("  update-tool sign <manifest.json> --key <private.key> [--out <sigfile>]");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
    }
    match args[1].as_str() {
        "gen-key" => {
            let prefix = PathBuf::from(&args[2]);
            let mut rng = rand::thread_rng();
            let signing = SigningKey::generate(&mut rng);
            let seed_b64 = B64.encode(signing.to_bytes());
            let pub_b64 = B64.encode(signing.verifying_key().to_bytes());
            let key_path = prefix.with_extension("key");
            let pub_path = prefix.with_extension("pub");
            fs::write(&key_path, format!("{seed_b64}\n")).expect("write key");
            fs::write(&pub_path, format!("{pub_b64}\n")).expect("write pub");
            println!("wrote private: {}", key_path.display());
            println!("wrote public:  {}", pub_path.display());
            println!("KEEP THE .key OFFLINE. Never commit it.");
        }
        "sign" => {
            let manifest = PathBuf::from(&args[2]);
            let key_flag = args.iter().position(|a| a == "--key").expect("missing --key");
            let key_path = PathBuf::from(&args[key_flag + 1]);
            let out = args
                .iter()
                .position(|a| a == "--out")
                .map(|i| PathBuf::from(&args[i + 1]))
                .unwrap_or_else(|| {
                    let mut name = manifest.as_os_str().to_owned();
                    name.push(".minisig");
                    PathBuf::from(name)
                });
            let seed_text = fs::read_to_string(&key_path).expect("read key");
            let seed_vec = B64.decode(seed_text.trim()).expect("key must be base64");
            let seed: [u8; 32] = seed_vec.try_into().expect("key must be 32 bytes");
            let signing = SigningKey::from_bytes(&seed);
            let bytes = fs::read(&manifest).expect("read manifest");
            let sig = signing.sign(&bytes);
            fs::write(&out, format!("{}\n", B64.encode(sig.to_bytes()))).expect("write sig");
            println!("signed {} -> {}", manifest.display(), out.display());
            println!("pubkey (bake into update_keys.rs): {}", B64.encode(signing.verifying_key().to_bytes()));
        }
        _ => usage(),
    }
}
