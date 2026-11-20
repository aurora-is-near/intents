use defuse_crypto::ed25519::Ed25519PublicKey;
use defuse_wallet::{RequestMessage, offchain::OffchainMessage};
use serde_json::{Map, Value, json};

pub use defuse_wallet_readable::{MAX_SIGNING_MESSAGE_BYTES, OFFCHAIN_PREFIX, REQUEST_PREFIX};

/// A message cannot be signed by this schema.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error(transparent)]
    Readable(#[from] defuse_wallet_readable::MessageError),
    #[error("text must be ASCII without DEL")]
    Text,
    #[error("text is not a readable v1 message")]
    Display,
    #[error("signing message exceeds 16 KiB")]
    TooLarge,
}

/// Stellar account ID of the key: `G...` strkey.
pub fn stellar_address(public_key: &Ed25519PublicKey) -> String {
    stellar_strkey::ed25519::PublicKey(public_key.0)
        .to_string()
        .as_str()
        .to_owned()
}

/// Reconstruct the readable v1 execution message for this Stellar key.
pub fn request_signing_message(
    public_key: &Ed25519PublicKey,
    msg: &RequestMessage,
) -> Result<String, MessageError> {
    let address = stellar_address(public_key);
    let text =
        defuse_wallet_readable::request_signing_message(&[("stellar_address", &address)], msg)?;

    document(REQUEST_PREFIX, &text)
}

/// Reconstruct all five NEP-641 fields, preserving the exact payload string.
pub fn offchain_signing_message(
    public_key: &Ed25519PublicKey,
    msg: &OffchainMessage,
) -> Result<String, MessageError> {
    let address = stellar_address(public_key);
    let text =
        defuse_wallet_readable::offchain_signing_message(&[("stellar_address", &address)], msg)?;

    document(OFFCHAIN_PREFIX, &text)
}

/// The readable v1 `text` as one JSON document: its prefix lines in `about`,
/// its warning lines in `warnings`, then its JSON fields.
///
/// The document is `JSON.stringify(JSON.parse(message), null, 2) + "\n"`, so
/// a wallet that parses and prints it (as Freighter does) shows the signed
/// text. The final LF is signed.
fn document(prefix: &str, text: &str) -> Result<String, MessageError> {
    let rest = text.strip_prefix(prefix).ok_or(MessageError::Display)?;

    // Warning lines, one empty line, then the JSON.
    let json = if rest.starts_with("{\n") {
        0
    } else {
        rest.find("\n\n{\n").ok_or(MessageError::Display)? + 2
    };
    let (warnings, json) = rest.split_at(json);
    let fields: Map<String, Value> =
        serde_json::from_str(json).map_err(|_| MessageError::Display)?;

    let mut document = Map::new();
    document.insert("about".to_owned(), json!(lines(prefix)));
    document.insert("warnings".to_owned(), json!(lines(warnings)));

    for (name, value) in fields {
        if document.insert(name, value).is_some() {
            return Err(MessageError::Display);
        }
    }

    let document = Value::Object(document);

    if !shown_as_signed(&document) {
        return Err(MessageError::Text);
    }

    let mut message = serde_json::to_string_pretty(&document)
        .map_err(defuse_wallet_readable::MessageError::from)?;
    message.push('\n');

    if message.len() > MAX_SIGNING_MESSAGE_BYTES {
        return Err(MessageError::TooLarge);
    }

    Ok(message)
}

fn lines(text: &str) -> Vec<&str> {
    text.lines().filter(|line| !line.is_empty()).collect()
}

/// Whether a wallet that parses the document shows its text as signed: all
/// text is ASCII without DEL, so the readable format has no `\uXXXX` escape
/// that JavaScript would show as the character itself (bidirectional
/// controls, look-alike letters).
///
/// Key order and numbers need no check: the readable format admits only
/// objects in JavaScript key order and integers within ±(2^53 - 1).
fn shown_as_signed(value: &Value) -> bool {
    let ascii = |text: &str| text.bytes().all(|byte| byte < 0x7f);

    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(text) => ascii(text),
        Value::Array(items) => items.iter().all(shown_as_signed),
        Value::Object(object) => object
            .iter()
            .all(|(key, value)| ascii(key) && shown_as_signed(value)),
    }
}
