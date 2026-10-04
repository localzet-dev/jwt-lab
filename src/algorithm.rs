#[derive(Debug)]
pub enum AlgorithmError {
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    // HMAC
    #[default]
    HS256,
    HS384,
    HS512,

    // ECDSA
    ES256,
    ES384,
    ES512,
    ES256K,

    // RSA PKCS#1 v1.5
    RS256,
    RS384,
    RS512,

    // RSA-PSS
    PS256,
    PS384,
    PS512,

    // EdDSA
    Ed25519,
    Ed448,

    // Post-quantum ML-DSA
    MLDSA44,
    MLDSA65,
    MLDSA87,
}

impl Algorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",

            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::ES256K => "ES256K",

            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",

            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",

            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",

            Self::MLDSA44 => "ML-DSA-44",
            Self::MLDSA65 => "ML-DSA-65",
            Self::MLDSA87 => "ML-DSA-87",
        }
    }
}

impl TryFrom<&str> for Algorithm {
    type Error = AlgorithmError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),

            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "ES512" => Ok(Self::ES512),
            "ES256K" => Ok(Self::ES256K),

            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),

            "PS256" => Ok(Self::PS256),
            "PS384" => Ok(Self::PS384),
            "PS512" => Ok(Self::PS512),

            "Ed25519" => Ok(Self::Ed25519),
            "Ed448" => Ok(Self::Ed448),

            "ML-DSA-44" => Ok(Self::MLDSA44),
            "ML-DSA-65" => Ok(Self::MLDSA65),
            "ML-DSA-87" => Ok(Self::MLDSA87),

            value => Err(AlgorithmError::Unsupported(value.to_owned())),
        }
    }
}
