//! Deterministic readable v1 messages shared by wallet signing schemas.

use std::fmt::Write;

use crate::{
    AccountId, NearPromise, NearToken, Request, RequestMessage, WalletOp,
    actions::{DeterministicStateInit, FunctionCall, NearAction, Transfer},
    offchain::OffchainMessage,
};
use serde_json::{Map, Value, json};

/// Maximum UTF-8 message size accepted by this schema (16 KiB).
pub const MAX_SIGNING_MESSAGE_BYTES: usize = 16 * 1024;
/// Domain and purpose separator for execution requests.
pub const REQUEST_PREFIX: &str = "NEAR Wallet Contract: execute request (v1)\nThis signature authorizes NEAR wallet operations, not a login.\nGas is in gas units.\nFunction arguments and deployment state may be opaque: verify them before signing.\n\n";
/// Domain and purpose separator for NEP-641 authorizations.
pub const OFFCHAIN_PREFIX: &str = "NEAR Wallet Contract: offchain authorization (v1)\nThis signature authorizes the exact payload below, not a NEAR transaction.\nThe consuming application defines expiration and one-time-use requirements.\n\n";

/// A message cannot be represented by this schema.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("unsupported action")]
    UnsupportedAction,
    #[error("function call arguments must be compact JSON")]
    FunctionArgs,
    #[error("NEP-141 transfers need one require_ft_metadata operation for their token")]
    TokenMetadata,
    #[error("NEP-141 transfer amount must be a decimal u128 string")]
    TokenAmount,
    #[error("timestamp must fit unsigned 64-bit Unix nanoseconds")]
    Timestamp,
    #[error("timeout must be a whole number of seconds fitting u32")]
    Timeout,
    #[error("signing identity field collides with a message field")]
    IdentityField,
    #[error("signing message exceeds 16 KiB")]
    TooLarge,
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Top-level `(name, value)` fields that a schema reconstructs from its stored
/// public key, e.g. `[("sui_public_key", ..), ("sui_address", ..)]`.
/// Names must not collide with message fields.
pub type SigningIdentity<'a> = &'a [(&'a str, &'a str)];

/// Reconstruct the full readable execution message.
///
/// Includes every execution field, explicit defaults, and the signing identity.
pub fn request_signing_message(
    identity: SigningIdentity<'_>,
    msg: &RequestMessage,
) -> Result<String, MessageError> {
    // No `..` here and below: a new field fails to compile until it is rendered.
    let RequestMessage {
        pay_for_gas,
        chain_id,
        signer_id,
        nonce,
        created_at,
        timeout,
        request: Request { internal, external },
    } = msg;
    u64::try_from(created_at.as_nanos()).map_err(|_| MessageError::Timestamp)?;
    let timeout_secs = u32::try_from(timeout.as_secs()).map_err(|_| MessageError::Timeout)?;
    if timeout.subsec_nanos() != 0 {
        return Err(MessageError::Timeout);
    }
    let tokens = tokens(internal)?;
    let external = external
        .iter()
        .map(|promise| promise_value(promise, &tokens))
        .collect::<Result<_, _>>()?;
    render(
        REQUEST_PREFIX,
        identity,
        object([
            ("chain_id", json!(chain_id)),
            ("signer_id", json!(signer_id)),
            ("nonce", json!(nonce)),
            ("created_at", json!(created_at)),
            ("timeout_secs", json!(timeout_secs)),
            ("pay_for_gas", json!(pay_for_gas)),
            (
                "request",
                Value::Object(object([
                    ("internal", sorted(json!(internal))),
                    ("external", Value::Array(external)),
                ])),
            ),
        ]),
    )
}

/// Reconstruct the exact bytes for all five NEP-641 message fields.
///
/// The payload is an opaque string: its bytes are never parsed or normalized.
pub fn offchain_signing_message(
    identity: SigningIdentity<'_>,
    msg: &OffchainMessage,
) -> Result<String, MessageError> {
    let OffchainMessage {
        chain_id,
        signer_id,
        path,
        timestamp,
        payload,
    } = msg;
    u64::try_from(timestamp.as_nanos()).map_err(|_| MessageError::Timestamp)?;
    render(
        OFFCHAIN_PREFIX,
        identity,
        object([
            ("chain_id", json!(chain_id)),
            ("signer_id", json!(signer_id)),
            ("path", json!(path)),
            ("timestamp", json!(timestamp)),
            ("payload", json!(payload)),
        ]),
    )
}

/// NEP-141 methods whose `amount` argument is shown with the token's decimals and symbol.
const FT_TRANSFER_METHODS: [&str; 2] = ["ft_transfer", "ft_transfer_call"];

/// Decimals and symbol of each token from `require_ft_metadata` operations,
/// which the contract checks against `ft_metadata()` before the transfer.
type Tokens<'a> = Vec<(&'a AccountId, u8, &'a str)>;

fn tokens(internal: &[WalletOp]) -> Result<Tokens<'_>, MessageError> {
    let mut tokens = Tokens::new();
    for op in internal {
        if let WalletOp::RequireFtMetadata {
            token_id,
            decimals,
            symbol,
        } = op
        {
            if tokens.iter().any(|(other, ..)| *other == token_id) {
                return Err(MessageError::TokenMetadata);
            }
            tokens.push((token_id, *decimals, symbol));
        }
    }
    Ok(tokens)
}

fn promise_value(promise: &NearPromise, tokens: &Tokens<'_>) -> Result<Value, MessageError> {
    let NearPromise {
        receiver_id,
        refund_to,
        actions,
    } = promise;
    let token = tokens
        .iter()
        .find(|(token_id, ..)| *token_id == receiver_id)
        .map(|&(_, decimals, symbol)| (decimals, symbol));
    let actions = actions
        .iter()
        .map(|action| action_value(action, token))
        .collect::<Result<_, _>>()?;
    Ok(Value::Object(object([
        ("receiver_id", json!(receiver_id)),
        ("refund_to", json!(refund_to)),
        ("actions", Value::Array(actions)),
    ])))
}

fn action_value(action: &NearAction, token: Option<(u8, &str)>) -> Result<Value, MessageError> {
    Ok(Value::Object(match action {
        NearAction::Transfer(Transfer { amount }) => {
            object([("action", json!("transfer")), ("amount", near(*amount))])
        }
        NearAction::FunctionCall(FunctionCall {
            function_name,
            args,
            deposit,
            gas,
            gas_weight,
        }) => {
            let token = if FT_TRANSFER_METHODS.contains(&function_name.as_str()) {
                Some(token.ok_or(MessageError::TokenMetadata)?)
            } else {
                None
            };
            object([
                ("action", json!("function_call")),
                ("function_name", json!(function_name)),
                ("args", args_value(args, token)?),
                ("deposit", near(*deposit)),
                ("gas", json!(gas.as_gas().to_string())),
                ("gas_weight", json!(gas_weight.to_string())),
            ])
        }
        NearAction::DeterministicStateInit(DeterministicStateInit {
            state_init,
            deposit,
        }) => object([
            ("action", json!("deterministic_state_init")),
            ("state_init", sorted(json!(state_init))),
            ("deposit", near(*deposit)),
        ]),
        _ => return Err(MessageError::UnsupportedAction),
    }))
}

/// Function arguments are shown as JSON in their original key order.
///
/// They must be exactly the compact serialization of that JSON (no extra
/// whitespace, duplicate keys, optional escapes or alternative number forms),
/// so the message determines the argument bytes. Anything else, including
/// empty and binary arguments, is rejected, as is JSON that JavaScript would
/// serialize differently (see [`portable`]).
///
/// With a `token`, the NEP-141 `amount` is shown with its decimals and symbol.
/// It must be a canonical decimal string, so the shown amount and decimals
/// determine it.
fn args_value(args: &[u8], token: Option<(u8, &str)>) -> Result<Value, MessageError> {
    let mut value: Value = serde_json::from_slice(args).map_err(|_| MessageError::FunctionArgs)?;
    if !portable(&value) || serde_json::to_vec(&value)? != args {
        return Err(MessageError::FunctionArgs);
    }
    if let Some((decimals, symbol)) = token {
        let amount = value.get_mut("amount").ok_or(MessageError::TokenAmount)?;
        let units = amount
            .as_str()
            .and_then(|text| {
                text.parse::<u128>()
                    .ok()
                    .filter(|units| units.to_string() == text)
            })
            .ok_or(MessageError::TokenAmount)?;
        *amount = json!(token_amount(units, decimals, symbol));
    }
    Ok(value)
}

/// Largest integer that JavaScript numbers represent exactly (2^53 - 1).
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Whether `JSON.stringify(JSON.parse(..))` gives the same compact bytes as
/// `serde_json`: numbers are integers within ±(2^53 - 1), and objects list
/// array-index keys first, in ascending order, as JavaScript objects do.
/// `serde_json` itself rejects unpaired surrogates.
fn portable(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => true,
        Value::Number(number) => number
            .as_i64()
            .is_some_and(|n| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n)),
        Value::Array(items) => items.iter().all(portable),
        Value::Object(object) => {
            object
                .keys()
                .is_sorted_by_key(|key| array_index(key).unwrap_or(u32::MAX))
                && object.values().all(portable)
        }
    }
}

/// JavaScript array index: a canonical decimal below 2^32 - 1.
fn array_index(key: &str) -> Option<u32> {
    key.parse()
        .ok()
        .filter(|index: &u32| *index != u32::MAX && index.to_string() == key)
}

fn near(amount: NearToken) -> Value {
    json!(token_amount(amount.as_yoctonear(), 24, "NEAR"))
}

/// `units` with `decimals` fractional digits, without trailing zeros,
/// followed by the symbol, e.g. `1.5 USDC` for 1500000 units with 6 decimals.
fn token_amount(units: u128, decimals: u8, symbol: &str) -> String {
    let decimals = usize::from(decimals);
    let digits = format!("{units:0>width$}", width = decimals + 1);
    let (whole, fraction) = digits.split_at(digits.len() - decimals);
    match fraction.trim_end_matches('0') {
        "" => format!("{whole} {symbol}"),
        fraction => format!("{whole}.{fraction} {symbol}"),
    }
}

/// Message object with sorted keys. Its values are not re-sorted, so function
/// arguments keep their original key order.
fn object<const N: usize>(fields: [(&str, Value); N]) -> Map<String, Value> {
    let mut object: Map<_, _> = fields
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
    object.sort_keys();
    object
}

/// Model value (internal operations, state init) with keys sorted at every level.
fn sorted(mut value: Value) -> Value {
    value.sort_all_objects();
    value
}

fn render(
    prefix: &str,
    identity: SigningIdentity<'_>,
    mut fields: Map<String, Value>,
) -> Result<String, MessageError> {
    for &(name, value) in identity {
        if fields.insert(name.to_owned(), json!(value)).is_some() {
            return Err(MessageError::IdentityField);
        }
    }
    fields.sort_keys();
    let json = serde_json::to_string_pretty(&fields)?;
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::Timestamp;

    const IDENTITY: SigningIdentity<'static> = &[("test_public_key", "key")];

    fn request(internal: Vec<WalletOp>, function_name: &str, args: &[u8]) -> RequestMessage {
        RequestMessage {
            pay_for_gas: false,
            chain_id: "mainnet".to_string(),
            signer_id: "alice.near".parse().unwrap(),
            nonce: 1,
            created_at: Timestamp::UNIX_EPOCH,
            timeout: Duration::from_mins(1),
            request: Request {
                internal,
                external: vec![
                    NearPromise::new("token.near".parse::<AccountId>().unwrap())
                        .function_call(FunctionCall::name(function_name).args(args)),
                ],
            },
        }
    }

    fn call(args: &[u8]) -> RequestMessage {
        request(Vec::new(), "submit", args)
    }

    fn ft_transfer(internal: Vec<WalletOp>, amount: &str) -> RequestMessage {
        let args = format!(r#"{{"receiver_id":"intents.near","amount":{amount},"msg":""}}"#);
        request(internal, "ft_transfer_call", args.as_bytes())
    }

    fn usdc(token_id: &str) -> WalletOp {
        WalletOp::require_ft_metadata(token_id.parse::<AccountId>().unwrap(), 6, "USDC")
    }

    /// Signed JSON document of a rendered request message.
    fn document(message: &str) -> Value {
        serde_json::from_str(message.strip_prefix(REQUEST_PREFIX).unwrap()).unwrap()
    }

    #[test]
    fn args_are_shown_once_in_original_order_and_determine_the_bytes() {
        let args = r#"{"receiver_id":"intents.near","amount":"1500000","msg":"{\"memo\":\"Оплата\"}","items":[{"z":null,"a":true}]}"#;
        let message = request_signing_message(IDENTITY, &call(args.as_bytes())).unwrap();
        assert!(message.contains(concat!(
            "            \"args\": {\n",
            "              \"receiver_id\": \"intents.near\",\n",
            "              \"amount\": \"1500000\",\n",
            "              \"msg\": \"{\\\"memo\\\":\\\"\\u041e\\u043f\\u043b\\u0430\\u0442\\u0430\\\"}\",\n",
            "              \"items\": [\n",
            "                {\n",
            "                  \"z\": null,\n",
            "                  \"a\": true\n",
            "                }\n",
            "              ]\n",
            "            },\n",
        )));
        assert!(!message.contains("args_"));
        let shown = &document(&message)["request"]["external"][0]["actions"][0]["args"];
        assert_eq!(serde_json::to_string(shown).unwrap(), args);
    }

    #[test]
    fn reordered_args_change_the_message() {
        assert_ne!(
            request_signing_message(IDENTITY, &call(br#"{"a":1,"b":2}"#)).unwrap(),
            request_signing_message(IDENTITY, &call(br#"{"b":2,"a":1}"#)).unwrap(),
        );
    }

    #[test]
    fn args_other_than_compact_json_are_rejected() {
        for args in [
            &b""[..],
            b"\x00\xff",
            b"\xef\xbb\xbf{}",
            b"not json",
            b" {}",
            b"{}\n",
            br#"{"a": 1}"#,
            br#"{"a":1,"a":2}"#,
            br#"{"a":"\u0041"}"#,
            br#"{"a":"\/"}"#,
            br#"{"a":1e3}"#,
            br#"{"a":1.50}"#,
            br#"{"a":-0}"#,
            br#"{"a":18446744073709551616}"#,
        ] {
            assert!(
                matches!(
                    request_signing_message(IDENTITY, &call(args)),
                    Err(MessageError::FunctionArgs)
                ),
                "accepted {:?}",
                String::from_utf8_lossy(args)
            );
        }
        for args in [
            &b"{}"[..],
            b"[]",
            b"null",
            b"\"text\"",
            br#"{"a":-1,"b":true}"#,
        ] {
            request_signing_message(IDENTITY, &call(args)).unwrap();
        }
    }

    #[test]
    fn args_have_the_same_compact_form_in_javascript() {
        // `JSON.stringify(JSON.parse(args)) == args` in JavaScript, too.
        for args in [
            &br#"{"a":-9007199254740991,"b":9007199254740991}"#[..],
            br#"{"0":1,"2":2,"10":3,"b":4,"4294967295":5,"a":6}"#,
            br#"[{"1":null},"x"]"#,
        ] {
            request_signing_message(IDENTITY, &call(args)).unwrap();
        }
        for args in [
            &br#"{"a":0.000001}"#[..],
            br#"{"a":0.5}"#,
            br#"{"a":1.0}"#,
            br#"{"a":100000000000000000000}"#,
            br#"{"a":9007199254740992}"#,
            br#"{"a":-9007199254740992}"#,
            br#"{"a":9007199254740993}"#,
            br#"{"a":"\ud800"}"#,
            br#"{"2":1,"1":2}"#,
            br#"{"a":1,"1":2}"#,
            br#"{"4294967295":1,"1":2}"#,
            br#"[{"b":1,"0":2}]"#,
        ] {
            assert!(
                matches!(
                    request_signing_message(IDENTITY, &call(args)),
                    Err(MessageError::FunctionArgs)
                ),
                "accepted {:?}",
                String::from_utf8_lossy(args)
            );
        }
    }

    #[test]
    fn amounts_have_decimals_and_symbol() {
        for (units, decimals, shown) in [
            (0, 24, "0 NEAR"),
            (1, 24, "0.000000000000000000000001 NEAR"),
            (10_u128.pow(24), 24, "1 NEAR"),
            (15 * 10_u128.pow(23), 24, "1.5 NEAR"),
            (
                u128::MAX,
                24,
                "340282366920938.463463374607431768211455 NEAR",
            ),
            (1_500_000, 6, "1.5 NEAR"),
            (1_500_000, 0, "1500000 NEAR"),
        ] {
            assert_eq!(token_amount(units, decimals, "NEAR"), shown);
        }
        let message = request_signing_message(
            IDENTITY,
            &RequestMessage {
                request: NearPromise::new("bob.near".parse::<AccountId>().unwrap())
                    .transfer(NearToken::from_millinear(1500))
                    .into(),
                ..call(b"{}")
            },
        )
        .unwrap();
        assert_eq!(
            document(&message)["request"]["external"][0]["actions"][0],
            json!({"action": "transfer", "amount": "1.5 NEAR"})
        );
        assert!(!message.contains("yocto"));
    }

    #[test]
    fn token_amounts_use_the_required_metadata() {
        let message = request_signing_message(
            IDENTITY,
            &ft_transfer(vec![usdc("token.near")], r#""1500000""#),
        )
        .unwrap();
        let document = document(&message);
        assert_eq!(
            document["request"]["internal"][0],
            json!({
                "op": "require_ft_metadata",
                "payload": {"token_id": "token.near", "decimals": 6, "symbol": "USDC"},
            })
        );
        assert_eq!(
            document["request"]["external"][0]["actions"][0],
            json!({
                "action": "function_call",
                "function_name": "ft_transfer_call",
                "args": {"receiver_id": "intents.near", "amount": "1.5 USDC", "msg": ""},
                "deposit": "0 NEAR",
                "gas": "50000000000000",
                "gas_weight": "1",
            })
        );
    }

    #[test]
    fn token_transfers_need_metadata_and_a_canonical_amount() {
        for internal in [
            Vec::new(),
            vec![usdc("other.near")],
            vec![usdc("token.near"), usdc("token.near")],
        ] {
            assert!(matches!(
                request_signing_message(IDENTITY, &ft_transfer(internal, r#""1""#)),
                Err(MessageError::TokenMetadata)
            ));
        }
        for amount in [
            r#""01""#,
            r#""+1""#,
            r#""1.5""#,
            r#""""#,
            "1",
            "null",
            r#""340282366920938463463374607431768211456""#,
        ] {
            assert!(
                matches!(
                    request_signing_message(
                        IDENTITY,
                        &ft_transfer(vec![usdc("token.near")], amount)
                    ),
                    Err(MessageError::TokenAmount)
                ),
                "accepted {amount}"
            );
        }
        assert!(matches!(
            request_signing_message(
                IDENTITY,
                &request(
                    vec![usdc("token.near")],
                    "ft_transfer",
                    br#"{"receiver_id":"bob.near"}"#
                )
            ),
            Err(MessageError::TokenAmount)
        ));
    }

    #[test]
    fn identity_cannot_replace_message_fields() {
        assert!(matches!(
            request_signing_message(&[("nonce", "2")], &call(b"{}")),
            Err(MessageError::IdentityField)
        ));
    }
}
