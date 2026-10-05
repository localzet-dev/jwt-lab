// SPDX-FileCopyrightText: 2026 Ivan Zorin <creator@localzet.com> (Localzet contributions)
// SPDX-License-Identifier: AGPL-3.0
mod algorithm;
mod b64u;
mod crypto;
mod jwt;

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

use serde::{Deserialize, Serialize};

const ISSUER: &str = "jwtgate";

#[derive(Debug, Parser)]
#[command(
    name = "jwtgate",
    version,
    about = "Small async JWT CLI written in Rust"
)]
struct Cli {
    /// Path to HMAC signing key
    #[arg(long, global = true, default_value = ".jwtgate.key")]
    key: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a new signing key
    Init,

    /// Create a JWT
    Issue {
        /// Subject
        #[arg(long)]
        sub: String,

        /// Token lifetime in seconds
        #[arg(long, default_value_t = 3600)]
        ttl: u64,

        /// Roles. May be specified multiple times.
        #[arg(long = "role")]
        roles: Vec<String>,
    },

    /// Verify signature + token expiration
    Verify { token: String },

    /// Decode a token WITHOUT verification
    Inspect { token: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    /// Issuer
    iss: String,

    /// Subject
    sub: String,

    /// Issued at
    iat: u64,

    /// Expiration
    exp: u64,

    /// Custom claim
    roles: Vec<String>,
}

trait Envelope {
    fn seal(&self, jwt: &str) -> Result<String>;

    fn open(&self, token: &str) -> Result<String>;
}

/// JWT -> JWT.
struct PlainEnvelope;

impl Envelope for PlainEnvelope {
    fn seal(&self, jwt: &str) -> Result<String> {
        Ok(jwt.to_owned())
    }

    fn open(&self, token: &str) -> Result<String> {
        Ok(token.to_owned())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let envelope = PlainEnvelope;

    match cli.command {
        Command::Init => {
            init(&cli.key).await?;
        }

        Command::Issue { sub, ttl, roles } => {
            let key = load_key(&cli.key).await?;

            let jwt = issue(&key, sub, ttl, roles)?;

            let token = envelope.seal(&jwt)?;

            println!("{token}");
        }

        Command::Verify { token } => {
            let key = load_key(&cli.key).await?;

            let jwt = envelope.open(&token)?;

            let claims = verify(&key, &jwt)?;

            println!("{}", serde_json::to_string_pretty(&claims)?);
        }

        Command::Inspect { token } => {
            let jwt = envelope.open(&token)?;

            inspect(&jwt)?;
        }
    }

    Ok(())
}

async fn init(path: &Path) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|err| anyhow!("failed to generate random key: {err}"))?;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await.with_context(|| {
        format!(
            "failed to create key {} (existing files are preserved)",
            path.display()
        )
    })?;
    file.write_all(&key).await?;
    file.sync_all().await?;

    println!("generated key: {}", path.display());

    Ok(())
}

async fn load_key(path: &Path) -> Result<Vec<u8>> {
    let key = tokio::fs::read(path).await.with_context(|| {
        format!(
            "failed to read key {}. Run `jwtgate init` first",
            path.display()
        )
    })?;

    if key.len() < 32 {
        bail!(
            "signing key is too short: {} bytes; expected >= 32",
            key.len()
        );
    }

    Ok(key)
}

fn issue(key: &[u8], sub: String, ttl: u64, roles: Vec<String>) -> Result<String> {
    let now = unix_time()?;

    let exp = now
        .checked_add(ttl)
        .context("expiration timestamp overflow")?;

    let claims = Claims {
        iss: ISSUER.to_string(),
        sub,
        iat: now,
        exp,
        roles,
    };

    let header = Header::new(Algorithm::HS256);

    let token = encode(&header, &claims, &EncodingKey::from_secret(key))?;

    Ok(token)
}

fn verify(key: &[u8], token: &str) -> Result<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;
    validation.set_issuer(&[ISSUER]);

    let data = decode::<Claims>(token, &DecodingKey::from_secret(key), &validation)?;

    if data.claims.iss != ISSUER {
        bail!(
            "invalid issuer: expected {:?}, got {:?}",
            ISSUER,
            data.claims.iss
        );
    }

    Ok(data.claims)
}

fn inspect(token: &str) -> Result<()> {
    let data = insecure_decode::<Claims>(token)?;

    println!("algorithm: {:?}", data.header.alg);

    if let Some(kid) = data.header.kid {
        println!("kid: {kid}");
    }

    println!();
    println!("{}", serde_json::to_string_pretty(&data.claims)?);

    println!();
    eprintln!("WARNING: token was NOT verified");

    Ok(())
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_key() {
        let key = [7u8; 32];
        let token = issue(&key, "alice".into(), 60, vec!["reader".into()]).unwrap();
        let claims = verify(&key, &token).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.roles, ["reader"]);
        assert!(verify(&[8u8; 32], &token).is_err());
    }

    #[test]
    fn rejects_expired_issuer_and_other_algorithm() {
        let key = [7u8; 32];
        for (alg, issuer, exp) in [
            (Algorithm::HS256, ISSUER, 1),
            (Algorithm::HS256, "other", unix_time().unwrap() + 60),
            (Algorithm::HS384, ISSUER, unix_time().unwrap() + 60),
        ] {
            let claims = Claims {
                iss: issuer.into(),
                sub: "alice".into(),
                iat: 1,
                exp,
                roles: vec![],
            };
            let token =
                encode(&Header::new(alg), &claims, &EncodingKey::from_secret(&key)).unwrap();
            assert!(verify(&key, &token).is_err());
        }
    }

    #[tokio::test]
    async fn key_creation_is_exclusive() {
        let path = std::env::temp_dir().join(format!("jwt-lab-key-{}", std::process::id()));
        assert!(!path.exists());
        let result = async {
            init(&path).await?;
            let first = load_key(&path).await?;
            assert!(init(&path).await.is_err());
            assert_eq!(first, load_key(&path).await?);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path)?.permissions().mode() & 0o777,
                    0o600
                );
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        tokio::fs::remove_file(path).await.unwrap();
        result.unwrap();
    }
}
