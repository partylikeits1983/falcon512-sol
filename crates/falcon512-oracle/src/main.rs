use falcon_rust::falcon512::{keygen, sign_with_rng, PublicKey, Signature};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::io::{self, Write};

fn main() {
    if let Err(err) = run() {
        let _ = writeln!(io::stderr(), "{err}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("verify") => {
            let sig = decode_hex_arg(args.next(), "signature")?;
            let pk = decode_hex_arg(args.next(), "public key")?;
            let msg = decode_hex_arg(args.next(), "message")?;
            write_bool(verify_bytes(&sig, &pk, &msg))
        }
        Some("gen") => {
            let seed = decode_fixed_32(args.next(), "key seed")?;
            let rng_seed = decode_fixed_32(args.next(), "rng seed")?;
            let msg = decode_hex_arg(args.next(), "message")?;
            let (sig, pk) = generate_vector(seed, rng_seed, &msg);
            let mut encoded = String::from("0x");
            encoded.push_str(&hex::encode(sig));
            encoded.push_str(&hex::encode(pk));
            io::stdout()
                .write_all(encoded.as_bytes())
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        _ => Err("usage: falcon512-oracle verify <sig-hex> <pk-hex> <msg-hex> | gen <seed32-hex> <rng32-hex> <msg-hex>".into()),
    }
}

fn verify_bytes(signature: &[u8], public_key: &[u8], message: &[u8]) -> bool {
    let Ok(sig) = Signature::from_bytes(signature) else {
        return false;
    };
    let Ok(pk) = PublicKey::from_bytes(public_key) else {
        return false;
    };
    falcon_rust::falcon512::verify(message, &sig, &pk)
}

fn generate_vector(seed: [u8; 32], rng_seed: [u8; 32], message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (sk, pk) = keygen(seed);
    let mut rng = ChaCha20Rng::from_seed(rng_seed);
    let sig = sign_with_rng(message, &sk, &mut rng);
    (sig.to_bytes(), pk.to_bytes())
}

fn write_bool(value: bool) -> Result<(), String> {
    let output = if value { "0x01" } else { "0x00" };
    io::stdout()
        .write_all(output.as_bytes())
        .map_err(|e| e.to_string())
}

fn decode_hex_arg(arg: Option<String>, label: &str) -> Result<Vec<u8>, String> {
    let arg = arg.ok_or_else(|| format!("missing {label}"))?;
    let hex = arg.strip_prefix("0x").unwrap_or(&arg);
    hex::decode(hex).map_err(|e| format!("invalid {label} hex: {e}"))
}

fn decode_fixed_32(arg: Option<String>, label: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex_arg(arg, label)?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must be exactly 32 bytes"))
}
