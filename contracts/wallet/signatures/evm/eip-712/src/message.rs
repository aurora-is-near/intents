//! EIP-712 typed data derived from wallet messages.
//!
//! The contract builds the typed data itself; clients only sign it.

use defuse_wallet::{
    GlobalContractId, NearPromise, RequestMessage, StateInit, StateInitV1, WalletOp,
    actions::{DeterministicStateInit, FunctionCall, NearAction, Transfer},
    offchain::OffchainMessage,
    readable_message::{MAX_SIGNING_MESSAGE_BYTES, attached_near, json_args, near_amount},
};

use crate::eip712::{Hash, array, boolean, digest, dynamic, hash_struct, uint};

/// `EIP712Domain.name`. The domain has no `chainId` or `verifyingContract`:
/// NEAR networks and accounts are bound by message fields instead.
pub const DOMAIN_NAME: &str = "NEAR Wallet Contract";
/// `EIP712Domain.version`.
pub const DOMAIN_VERSION: &str = "1";

macro_rules! state_entry {
    () => {
        "StateEntry(bytes key,bytes value)"
    };
}
macro_rules! state_init {
    () => {
        "StateInit(string code_hash,string code_account_id,StateEntry[] data)"
    };
}
macro_rules! action {
    () => {
        "Action(string action,uint128 yocto_near,string function_name,string args,uint64 gas,uint64 gas_weight,StateInit[] state_init)"
    };
}
macro_rules! operation {
    () => {
        "Operation(string op,string account_id,string signature_mode,uint8 decimals,string symbol)"
    };
}
macro_rules! promise {
    () => {
        "Promise(string receiver_id,string refund_to,Action[] actions)"
    };
}

/// `encodeType` of each struct: its definition, then referenced types sorted by name.
pub const DOMAIN_TYPE: &str = "EIP712Domain(string name,string version)";
pub const REQUEST_TYPE: &str = concat!(
    "ExecuteRequest(string[] warnings,string chain_id,string signer_id,uint32 nonce,string created_at,uint32 timeout_secs,bool pay_for_gas,Operation[] internal,Promise[] external)",
    action!(),
    operation!(),
    promise!(),
    state_entry!(),
    state_init!(),
);
pub const OFFCHAIN_TYPE: &str = "OffchainAuthorization(string chain_id,string signer_id,string[] path,string timestamp,string payload)";
const OPERATION_TYPE: &str = operation!();
const PROMISE_TYPE: &str = concat!(promise!(), action!(), state_entry!(), state_init!());
const ACTION_TYPE: &str = concat!(action!(), state_entry!(), state_init!());
const STATE_INIT_TYPE: &str = concat!(state_init!(), state_entry!());
const STATE_ENTRY_TYPE: &str = state_entry!();

/// Text and bytes members (UTF-8 or raw length) in total, which bounds gas
/// and the wallet prompt together with [`MAX_ITEMS`].
pub const MAX_TEXT_BYTES: usize = MAX_SIGNING_MESSAGE_BYTES;
/// Array items in total: warnings, operations, promises, actions, state
/// inits, state entries and path entries.
pub const MAX_ITEMS: usize = 128;

/// A message cannot be signed as typed data.
#[derive(Debug, thiserror::Error)]
pub enum Eip712Error {
    #[error("unsupported action or method")]
    Unsupported,
    #[error("text must be printable ASCII")]
    Text,
    #[error("function call arguments must be compact ASCII JSON")]
    FunctionArgs,
    #[error("timestamp must fit unsigned 64-bit Unix nanoseconds")]
    Timestamp,
    #[error("timeout must be a whole number of seconds fitting u32")]
    Timeout,
    #[error("typed data exceeds 16 KiB of text and bytes or 128 items")]
    TooLarge,
}

/// `hashStruct(EIP712Domain)`.
pub fn domain_separator() -> Hash {
    hash_struct(DOMAIN_TYPE, [dynamic(DOMAIN_NAME), dynamic(DOMAIN_VERSION)])
}

/// Digest that the wallet signs for `ExecuteRequest`.
pub fn request_digest(msg: &RequestMessage) -> Result<Hash, Eip712Error> {
    // No `..` in destructuring: a new field fails to compile until it is encoded.
    let RequestMessage {
        pay_for_gas,
        chain_id,
        signer_id,
        nonce,
        created_at,
        timeout,
        request,
    } = msg;
    let timeout_secs = u32::try_from(timeout.as_secs()).map_err(|_| Eip712Error::Timeout)?;
    if timeout.subsec_nanos() != 0 {
        return Err(Eip712Error::Timeout);
    }
    // Each operation and promise is an item, too.
    if request.internal.len() + request.external.len() > MAX_ITEMS {
        return Err(Eip712Error::TooLarge);
    }
    // As in the readable format: each add_extension, then each promise whose
    // attached NEAR can be refunded to an account other than this wallet.
    let extensions = request.internal.iter().filter_map(|op| match op {
        WalletOp::AddExtension { account_id } => Some(format!(
            "add_extension gives {account_id} full control of this wallet"
        )),
        _ => None,
    });
    let refunds = request.external.iter().filter_map(|promise| {
        let refund_to = promise.refund_to.as_ref().filter(|id| *id != signer_id)?;
        let attached = attached_near(promise);
        (attached != 0).then(|| {
            format!(
                "up to {} sent to {} can be refunded to {refund_to}, not to this wallet",
                near_amount(attached),
                promise.receiver_id
            )
        })
    });
    let mut budget = Budget::default();
    let members = [
        budget.items(extensions.chain(refunds), Budget::text)?,
        budget.text(chain_id)?,
        budget.text(signer_id)?,
        uint(*nonce),
        budget.timestamp(*created_at)?,
        uint(timeout_secs),
        boolean(*pay_for_gas),
        budget.items(&request.internal, operation)?,
        budget.items(&request.external, promise)?,
    ];
    Ok(digest(
        &domain_separator(),
        &hash_struct(REQUEST_TYPE, members),
    ))
}

/// Digest that the wallet signs for NEP-641 `OffchainAuthorization`.
pub fn offchain_digest(msg: &OffchainMessage) -> Result<Hash, Eip712Error> {
    let OffchainMessage {
        chain_id,
        signer_id,
        path,
        timestamp,
        payload,
    } = msg;
    let mut budget = Budget::default();
    let members = [
        budget.text(chain_id)?,
        budget.text(signer_id)?,
        budget.items(path, Budget::text)?,
        budget.timestamp(*timestamp)?,
        budget.text(payload)?,
    ];
    Ok(digest(
        &domain_separator(),
        &hash_struct(OFFCHAIN_TYPE, members),
    ))
}

/// Encodes dynamic members and arrays within [`MAX_TEXT_BYTES`] and
/// [`MAX_ITEMS`], counting before any parsing or hashing.
#[derive(Default)]
struct Budget {
    bytes: usize,
    items: usize,
}

impl Budget {
    /// `bytes` member.
    fn bytes(&mut self, value: &[u8]) -> Result<Hash, Eip712Error> {
        self.bytes = self.bytes.saturating_add(value.len());
        if self.bytes > MAX_TEXT_BYTES {
            return Err(Eip712Error::TooLarge);
        }
        Ok(dynamic(value))
    }

    /// `string` member: printable ASCII only, so no hidden, bidirectional or
    /// look-alike characters are shown.
    fn text(&mut self, value: impl AsRef<str>) -> Result<Hash, Eip712Error> {
        let value = value.as_ref();
        let hash = self.bytes(value.as_bytes())?;
        if !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
            return Err(Eip712Error::Text);
        }
        Ok(hash)
    }

    /// RFC 3339 UTC, as in JSON.
    fn timestamp(&mut self, value: defuse_wallet::Timestamp) -> Result<Hash, Eip712Error> {
        u64::try_from(value.as_nanos()).map_err(|_| Eip712Error::Timestamp)?;
        let value = serde_json::to_value(value).map_err(|_| Eip712Error::Timestamp)?;
        self.text(value.as_str().ok_or(Eip712Error::Timestamp)?)
    }

    /// Array member.
    fn items<T>(
        &mut self,
        items: impl IntoIterator<Item = T>,
        mut encode: impl FnMut(&mut Self, T) -> Result<Hash, Eip712Error>,
    ) -> Result<Hash, Eip712Error> {
        let mut hashes = Vec::new();
        for item in items {
            self.items += 1;
            if self.items > MAX_ITEMS {
                return Err(Eip712Error::TooLarge);
            }
            hashes.push(encode(self, item)?);
        }
        Ok(array(hashes))
    }
}

/// Operations share one type; fields that an operation does not use are
/// empty or zero, and `op` tells which apply.
fn operation(budget: &mut Budget, op: &WalletOp) -> Result<Hash, Eip712Error> {
    let (name, account_id, signature_mode, decimals, symbol) = match op {
        WalletOp::SetSignatureMode { enable } => (
            "set_signature_mode",
            "",
            if *enable { "enable" } else { "disable" },
            0,
            "",
        ),
        WalletOp::AddExtension { account_id } => ("add_extension", account_id.as_str(), "", 0, ""),
        WalletOp::RemoveExtension { account_id } => {
            ("remove_extension", account_id.as_str(), "", 0, "")
        }
        WalletOp::RequireFtMetadata {
            token_id,
            decimals,
            symbol,
        } => (
            "require_ft_metadata",
            token_id.as_str(),
            "",
            *decimals,
            symbol.as_str(),
        ),
    };
    Ok(hash_struct(
        OPERATION_TYPE,
        [
            budget.text(name)?,
            budget.text(account_id)?,
            budget.text(signature_mode)?,
            uint(decimals),
            budget.text(symbol)?,
        ],
    ))
}

/// `refund_to` is empty when refunds go to this wallet.
fn promise(budget: &mut Budget, promise: &NearPromise) -> Result<Hash, Eip712Error> {
    let NearPromise {
        receiver_id,
        refund_to,
        actions,
    } = promise;
    Ok(hash_struct(
        PROMISE_TYPE,
        [
            budget.text(receiver_id)?,
            budget.text(refund_to.as_ref().map_or("", |id| id.as_str()))?,
            budget.items(actions, action)?,
        ],
    ))
}

/// Actions share one type; unused fields are empty or zero. `yocto_near` is
/// the transfer amount or attached deposit.
fn action(budget: &mut Budget, action: &NearAction) -> Result<Hash, Eip712Error> {
    let members = match action {
        NearAction::Transfer(Transfer { amount }) => [
            budget.text("transfer")?,
            uint(amount.as_yoctonear()),
            budget.text("")?,
            budget.text("")?,
            uint(0u8),
            uint(0u8),
            array([]),
        ],
        NearAction::FunctionCall(FunctionCall {
            function_name,
            args,
            deposit,
            gas,
            gas_weight,
        }) => {
            // Its request would be signed as an opaque string.
            if function_name == "w_execute_extension" {
                return Err(Eip712Error::Unsupported);
            }
            let name = budget.text("function_call")?;
            let name_hash = budget.text(function_name)?;
            // Counted before parsing; exact ASCII JSON bytes.
            let args_hash = budget.bytes(args)?;
            if !args.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
                return Err(Eip712Error::FunctionArgs);
            }
            let value = json_args(args).map_err(|_| Eip712Error::FunctionArgs)?;
            token_args(function_name, &value)?;
            [
                name,
                uint(deposit.as_yoctonear()),
                name_hash,
                args_hash,
                uint(gas.as_gas()),
                uint(*gas_weight),
                array([]),
            ]
        }
        NearAction::DeterministicStateInit(DeterministicStateInit {
            state_init,
            deposit,
        }) => [
            budget.text("deterministic_state_init")?,
            uint(deposit.as_yoctonear()),
            budget.text("")?,
            budget.text("")?,
            uint(0u8),
            uint(0u8),
            budget.items([state_init], state_init_hash)?,
        ],
        _ => return Err(Eip712Error::Unsupported),
    };
    Ok(hash_struct(ACTION_TYPE, members))
}

/// NEP-141 transfer methods with their parameters, as in the readable format:
/// other keys, which the token would ignore, could imitate the amount.
const FT_TRANSFER_METHODS: [(&str, &[&str]); 2] = [
    ("ft_transfer", &["receiver_id", "amount", "memo"]),
    (
        "ft_transfer_call",
        &["receiver_id", "amount", "memo", "msg"],
    ),
];

/// NEP-141 transfers take only the method's parameters and a canonical
/// decimal `u128` amount (in base units).
fn token_args(function_name: &str, args: &serde_json::Value) -> Result<(), Eip712Error> {
    let Some((_, keys)) = FT_TRANSFER_METHODS
        .iter()
        .find(|(method, _)| *method == function_name)
    else {
        return Ok(());
    };
    let object = args.as_object().ok_or(Eip712Error::FunctionArgs)?;
    let canonical = object
        .get("amount")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|text| {
            text.parse::<u128>()
                .is_ok_and(|units| units.to_string() == text)
        });
    if !canonical || object.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(Eip712Error::FunctionArgs);
    }
    Ok(())
}

/// The code is a base58 hash or an account ID; the other one is empty.
/// Entries are in key order.
fn state_init_hash(budget: &mut Budget, state_init: &StateInit) -> Result<Hash, Eip712Error> {
    let StateInit::V1(StateInitV1 { code, data }) = state_init;
    let (code_hash, code_account_id) = match code {
        GlobalContractId::CodeHash(hash) => (bs58::encode(hash).into_string(), ""),
        GlobalContractId::AccountId(account_id) => (String::new(), account_id.as_str()),
    };
    Ok(hash_struct(
        STATE_INIT_TYPE,
        [
            budget.text(code_hash)?,
            budget.text(code_account_id)?,
            budget.items(data, |budget, (key, value)| {
                Ok(hash_struct(
                    STATE_ENTRY_TYPE,
                    [budget.bytes(key)?, budget.bytes(value)?],
                ))
            })?,
        ],
    ))
}
