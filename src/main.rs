mod algorithm;
mod b64u;
mod jwt;
mod crypto;

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};



use serde::{Deserialize, Serialize};

const ISSUER: &str = "jwtgate";
const TYPE: &str = "LWTv4";



//
// CLI
//

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
    Verify {
        token: String,
    },

    /// Decode a token WITHOUT verification
    Inspect {
        token: String,
    },
}

//
// JWT
//

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

//
// Вот сюда потом воткнёшь LWT.
//
// JWT core вообще не обязан знать,
// во что ты заворачиваешь итоговый JWT.
//

trait Envelope {
    fn seal(&self, jwt: &str) -> Result<String>;

    fn open(&self, token: &str) -> Result<String>;
}

/// Сейчас ничего не делает.
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

//
// Main
//

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Позже:
    //
    // let envelope = LwtEnvelope::new(...);
    //
    let envelope = PlainEnvelope;

    match cli.command {
        Command::Init => {
            init(&cli.key).await?;
        }

        Command::Issue {
            sub,
            ttl,
            roles,
        } => {
            let key = load_key(&cli.key).await?;

            let jwt = issue(&key, sub, ttl, roles)?;

            let token = envelope.seal(&jwt)?;

            println!("{token}");
        }

        Command::Verify { token } => {
            let key = load_key(&cli.key).await?;

            // LWT -> JWT
            let jwt = envelope.open(&token)?;

            let claims = verify(&key, &jwt)?;

            println!("{}", serde_json::to_string_pretty(&claims)?);
        }

        Command::Inspect { token } => {
            // Если LWT потом будет зашифрован,
            // здесь сначала будет envelope.open().
            let jwt = envelope.open(&token)?;

            inspect(&jwt)?;
        }
    }

    Ok(())
}

//
// Commands
//

async fn init(path: &Path) -> Result<()> {
    if tokio::fs::metadata(path).await.is_ok() {
        bail!(
            "key already exists: {}",
            path.display()
        );
    }

    //
    // 256-bit random HMAC secret
    //
    let mut key = [0u8; 32];

    getrandom::fill(&mut key)
        .map_err(|err| anyhow!("failed to generate random key: {err}"))?;

    tokio::fs::write(path, key)
        .await
        .with_context(|| {
            format!("failed to write {}", path.display())
        })?;

    println!("generated key: {}", path.display());

    Ok(())
}

async fn load_key(path: &Path) -> Result<Vec<u8>> {
    let key = tokio::fs::read(path)
        .await
        .with_context(|| {
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

fn issue(
    key: &[u8],
    sub: String,
    ttl: u64,
    roles: Vec<String>,
) -> Result<String> {
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

    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret(key),
    )?;

    Ok(token)
}

fn verify(
    key: &[u8],
    token: &str,
) -> Result<Claims> {
    //
    // ВАЖНО:
    // разрешаем только HS256.
    //
    // Не надо брать алгоритм из JWT
    // и слепо ему доверять.
    //
    let validation = Validation::new(Algorithm::HS256);

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(key),
        &validation,
    )?;

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
    //
    // Только декодирование.
    // НИКАКОЙ проверки подписи.
    //
    let data = insecure_decode::<Claims>(token)?;

    println!("algorithm: {:?}", data.header.alg);

    if let Some(kid) = data.header.kid {
        println!("kid: {kid}");
    }

    println!();
    println!(
        "{}",
        serde_json::to_string_pretty(&data.claims)?
    );

    println!();
    println!("WARNING: token was NOT verified");

    Ok(())
}

fn unix_time() -> Result<u64> {
    Ok(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
    )
}