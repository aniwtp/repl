//! `repl-keygen <node_id> <out_dir>` — self-signed Ed25519 identity for a node.
//! Writes `<node_id>.crt` / `<node_id>.key` and prints the `REPL_PEERS` entry.

use std::os::unix::fs::PermissionsExt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(node), Some(dir)) = (args.next(), args.next()) else {
        eprintln!("usage: repl-keygen <node_id> <out_dir>");
        std::process::exit(2);
    };
    let g = repl::tls::generate(&node)?;
    std::fs::create_dir_all(&dir)?;
    let (crt, key) = (format!("{dir}/{node}.crt"), format!("{dir}/{node}.key"));
    std::fs::write(&crt, g.cert_pem)?;
    std::fs::write(&key, g.key_pem)?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    println!("{node}=sha256:{}", repl::tls::pin_hex(&g.pin));
    Ok(())
}
