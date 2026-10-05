use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    pub alg: String,

    #[serde(default = "jwt_type")]
    pub typ: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

fn jwt_type() -> String {
    "JWT".into()
}
