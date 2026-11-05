//! Deterministic readable v1 messages shared by wallet signing schemas.

use std::fmt::Write;

use crate::{NearPromise, RequestMessage, actions::NearAction, offchain::OffchainMessage};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

/// Maximum UTF-8 message size accepted by this schema (16 KiB).
pub const MAX_SIGNING_MESSAGE_BYTES: usize = 16 * 1024;
/// Domain and purpose separator for execution requests.
pub const REQUEST_PREFIX: &str = "NEAR Wallet Contract: execute request (v1)\nThis signature authorizes NEAR wallet operations, not a login.\nAmounts and deposits are in yoctoNEAR; gas is in gas units.\nFunction arguments and deployment state may be opaque: verify them before signing.\n\n";
/// Domain and purpose separator for NEP-641 authorizations.
pub const OFFCHAIN_PREFIX: &str = "NEAR Wallet Contract: offchain authorization (v1)\nThis signature authorizes the exact payload below, not a NEAR transaction.\nThe consuming application defines expiration and one-time-use requirements.\n\n";

/// A message cannot be represented by this schema.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("unsupported action")]
    UnsupportedAction,
    #[error("timestamp must fit unsigned 64-bit Unix nanoseconds")]
    Timestamp,
    #[error("timeout must be a whole number of seconds fitting u32")]
    Timeout,
    #[error("signing message exceeds 16 KiB")]
    TooLarge,
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Signing identity reconstructed by a schema from its stored public key.
#[derive(Debug, Clone, Copy)]
pub enum SigningIdentity<'a> {
    /// Phantom Solana v1 raw base58 public key.
    Solana { public_key: &'a str },
    /// Sui native base64 (flag plus key) and its directly derived address.
    Sui {
        public_key: &'a str,
        address: &'a str,
    },
}

impl SigningIdentity<'_> {
    fn bind(self, mut value: Value) -> Value {
        match self {
            Self::Solana { public_key } => value["solana_public_key"] = json!(public_key),
            Self::Sui {
                public_key,
                address,
            } => {
                value["sui_public_key"] = json!(public_key);
                value["sui_address"] = json!(address);
            }
        }
        value
    }
}

/// Reconstruct the full readable execution message.
///
/// Includes every execution field, explicit defaults, and the signing identity.
pub fn request_signing_message(
    identity: SigningIdentity<'_>,
    msg: &RequestMessage,
) -> Result<String, MessageError> {
    u64::try_from(msg.created_at.as_nanos()).map_err(|_| MessageError::Timestamp)?;
    let timeout = u32::try_from(msg.timeout.as_secs()).map_err(|_| MessageError::Timeout)?;
    if msg.timeout.subsec_nanos() != 0 {
        return Err(MessageError::Timeout);
    }
    let external = msg
        .request
        .external
        .iter()
        .map(promise_value)
        .collect::<Result<Vec<_>, _>>()?;
    render(
        REQUEST_PREFIX,
        identity.bind(json!({
            "chain_id": msg.chain_id,
            "signer_id": msg.signer_id,
            "nonce": msg.nonce,
            "created_at": msg.created_at,
            "timeout_secs": timeout,
            "pay_for_gas": msg.pay_for_gas,
            "request": { "internal": msg.request.internal, "external": external },
        })),
    )
}

/// Reconstruct the exact bytes for all five NEP-641 message fields.
///
/// The payload is an opaque string: its bytes are never parsed or normalized.
pub fn offchain_signing_message(
    identity: SigningIdentity<'_>,
    msg: &OffchainMessage,
) -> Result<String, MessageError> {
    u64::try_from(msg.timestamp.as_nanos()).map_err(|_| MessageError::Timestamp)?;
    render(
        OFFCHAIN_PREFIX,
        identity.bind(json!({
            "chain_id": msg.chain_id,
            "signer_id": msg.signer_id,
            "path": msg.path,
            "timestamp": msg.timestamp,
            "payload": msg.payload,
        })),
    )
}

fn promise_value(promise: &NearPromise) -> Result<Value, MessageError> {
    let actions = promise
        .actions
        .iter()
        .map(action_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(
        json!({ "receiver_id": promise.receiver_id, "refund_to": promise.refund_to, "actions": actions }),
    )
}

fn action_value(action: &NearAction) -> Result<Value, MessageError> {
    Ok(match action {
        NearAction::Transfer(transfer) => json!({
            "action": "transfer", "amount_yoctonear": transfer.amount.as_yoctonear().to_string(),
        }),
        NearAction::FunctionCall(call) => json!({
            "action": "function_call",
            "function_name": call.function_name,
            "args_base64": STANDARD.encode(&call.args),
            "args_utf8": std::str::from_utf8(&call.args).ok(),
            "deposit_yoctonear": call.deposit.as_yoctonear().to_string(),
            "gas": call.gas.as_gas().to_string(),
            "gas_weight": call.gas_weight.to_string(),
        }),
        NearAction::DeterministicStateInit(init) => json!({
            "action": "deterministic_state_init",
            "state_init": init.state_init,
            "deposit_yoctonear": init.deposit.as_yoctonear().to_string(),
        }),
        _ => return Err(MessageError::UnsupportedAction),
    })
}

fn render(prefix: &str, mut value: Value) -> Result<String, MessageError> {
    // Independent of serde_json's workspace-wide preserve_order feature.
    value.sort_all_objects();
    let json = serde_json::to_string_pretty(&value)?;
    let mut message = String::from(prefix);
    // Escape DEL and all non-ASCII characters, including bidi controls and line separators.
    // UTF-16 code units make the exact format reproducible in browser JavaScript.
    for unit in json.encode_utf16() {
        if unit <= 0x7e {
            message.push(char::from(u8::try_from(unit).expect("ASCII unit")));
        } else {
            write!(message, "\\u{unit:04x}").expect("String write");
        }
        if message.len() >= MAX_SIGNING_MESSAGE_BYTES {
            return Err(MessageError::TooLarge);
        }
    }
    message.push('\n');
    Ok(message)
}
