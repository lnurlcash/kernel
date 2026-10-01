//! Verify spends of [LUD-25](https://github.com/lnurl/luds) notes with
//! **Bitcoin Core's own script interpreter, unmodified**: `libbitcoinkernel`,
//! built from the pinned `vendor/bitcoin` tree and linked in statically.
//!
//! This is the Rust face of the `lnurlcash-kernel` Python package, and the
//! same split applies: this crate decides whether a witness stack spends a
//! note's taproot output key `Q`, and nothing else. Decoding `ck1`/`cw1`,
//! leaf rules and time claims belong to
//! [`lnurlcash-core`](https://github.com/lnurlcash/lnurlcash-core). This crate
//! never reads a clock.
//!
//! ```no_run
//! # let (output_key, script, control_block, preimage) = ([0u8; 32], vec![], vec![], vec![]);
//! let opens = lnurlcash_kernel::verify_script_path(
//!     &output_key,
//!     "mint.example",
//!     &script,
//!     &control_block,
//!     &[&preimage],
//!     0,           // the claimed nLockTime
//!     0xffff_ffff, // the claimed nSequence
//! )?;
//! # Ok::<(), lnurlcash_kernel::KernelError>(())
//! ```
//!
//! # The canonical spend transaction (version 2)
//!
//! Core verifies an input of a transaction, so a fixed minimal one is
//! assembled. Its shape is normative: every field is signed.
//!
//! | field | value |
//! |---|---|
//! | `nVersion` | `2` |
//! | `vin[0]` | prevout `(tagged_hash("LNURLcash/mint", domain), 0)`, empty scriptSig, `nSequence` = claimed |
//! | `vout[0]` | value `0`, empty scriptPubKey |
//! | `nLockTime` | claimed |
//! | spent output | `(OP_1 <Q>, 0)` |
//!
//! A key-path spend claims locktime `0` and sequence `0xffffffff`.

use std::{ffi::c_void, fmt};

use sha2::{Digest, Sha256};

/// The canonical spend transaction's `nVersion`.
pub const TX_VERSION: i32 = 2;
/// What a key-path spend claims: no time at all.
pub const KEY_PATH_LOCKTIME: u32 = 0;
pub const KEY_PATH_SEQUENCE: u32 = 0xffff_ffff;

/// The Bitcoin Core release this crate's verifier is built from.
pub const UPSTREAM_TAG: &str = "v31.1";
pub const UPSTREAM_COMMIT: &str = "9be056a8a72b624dae9623b2f7bded92c2a21c91";

/// Core's script verification flags.
pub mod flags {
    pub const P2SH: u32 = 1 << 0;
    pub const DERSIG: u32 = 1 << 2;
    pub const NULLDUMMY: u32 = 1 << 4;
    pub const CHECKLOCKTIMEVERIFY: u32 = 1 << 9;
    pub const CHECKSEQUENCEVERIFY: u32 = 1 << 10;
    pub const WITNESS: u32 = 1 << 11;
    pub const TAPROOT: u32 = 1 << 17;
    /// Every consensus flag, as LUD-25 requires.
    pub const ALL: u32 =
        P2SH | DERSIG | NULLDUMMY | CHECKLOCKTIMEVERIFY | CHECKSEQUENCEVERIFY | WITNESS | TAPROOT;
}

/// The library could not be asked: a malformed transaction or script handed
/// to it, or an invalid flag combination. A spend Core merely rejects is
/// `Ok(false)`, never this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// libbitcoinkernel refused to build one of its objects.
    Rejected(&'static str),
    /// `btck_script_pubkey_verify` could not run, with its status.
    Status(u8),
    /// A caller error: an empty domain, or too many inputs.
    Invalid(&'static str),
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Rejected(what) => write!(f, "libbitcoinkernel rejected the {what}"),
            KernelError::Status(status) => {
                write!(
                    f,
                    "btck_script_pubkey_verify failed to run (status {status})"
                )
            }
            KernelError::Invalid(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for KernelError {}

mod ffi {
    use std::ffi::c_void;

    extern "C" {
        pub fn btck_script_pubkey_create(script: *const c_void, len: usize) -> *mut c_void;
        pub fn btck_script_pubkey_destroy(script: *mut c_void);
        pub fn btck_transaction_create(tx: *const c_void, len: usize) -> *mut c_void;
        pub fn btck_transaction_destroy(tx: *mut c_void);
        pub fn btck_transaction_output_create(script: *const c_void, amount: i64) -> *mut c_void;
        pub fn btck_transaction_output_destroy(output: *mut c_void);
        pub fn btck_precomputed_transaction_data_create(
            tx: *const c_void,
            spent_outputs: *const *const c_void,
            spent_outputs_len: usize,
        ) -> *mut c_void;
        pub fn btck_precomputed_transaction_data_destroy(data: *mut c_void);
        pub fn btck_script_pubkey_verify(
            script_pubkey: *const c_void,
            amount: i64,
            tx_to: *const c_void,
            precomputed_txdata: *const c_void,
            input_index: u32,
            flags: u32,
            status: *mut u8,
        ) -> i32;
    }
}

/// A native object, freed exactly once.
struct Owned {
    ptr: *mut c_void,
    destroy: unsafe extern "C" fn(*mut c_void),
}

impl Owned {
    fn new(
        ptr: *mut c_void,
        destroy: unsafe extern "C" fn(*mut c_void),
        what: &'static str,
    ) -> Result<Self, KernelError> {
        if ptr.is_null() {
            return Err(KernelError::Rejected(what));
        }
        Ok(Owned { ptr, destroy })
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from the create call that pairs with `destroy`,
        // and is freed only here
        unsafe { (self.destroy)(self.ptr) }
    }
}

fn script_pubkey(script: &[u8]) -> Result<Owned, KernelError> {
    // SAFETY: Core copies the bytes; the slice outlives the call
    let ptr = unsafe { ffi::btck_script_pubkey_create(script.as_ptr().cast(), script.len()) };
    Owned::new(ptr, ffi::btck_script_pubkey_destroy, "script pubkey")
}

/// Ask Core whether input `input_index` of the serialized `tx` spends
/// `script_pubkey` worth `amount` sat. `spent_outputs` is `(scriptPubKey,
/// amount)` for every input of `tx`, in order: a taproot sighash commits to
/// all of them.
pub fn verify_input(
    script_pubkey: &[u8],
    amount: i64,
    tx: &[u8],
    spent_outputs: &[(&[u8], i64)],
    input_index: u32,
    flags: u32,
) -> Result<bool, KernelError> {
    // dependents are declared after what they borrow, so they drop first
    let spk = self::script_pubkey(script_pubkey)?;
    // SAFETY: as for script_pubkey
    let tx = Owned::new(
        unsafe { ffi::btck_transaction_create(tx.as_ptr().cast(), tx.len()) },
        ffi::btck_transaction_destroy,
        "transaction",
    )?;
    let mut spent_scripts = Vec::with_capacity(spent_outputs.len());
    let mut spent = Vec::with_capacity(spent_outputs.len());
    for (script, value) in spent_outputs {
        let script = self::script_pubkey(script)?;
        // SAFETY: `script` is a live script pubkey handle; Core copies it
        let output = unsafe { ffi::btck_transaction_output_create(script.ptr, *value) };
        spent.push(Owned::new(
            output,
            ffi::btck_transaction_output_destroy,
            "spent output",
        )?);
        spent_scripts.push(script);
    }
    let pointers: Vec<*const c_void> = spent.iter().map(|o| o.ptr as *const c_void).collect();
    // SAFETY: every handle is live for the duration of the call
    let txdata = Owned::new(
        unsafe {
            ffi::btck_precomputed_transaction_data_create(tx.ptr, pointers.as_ptr(), pointers.len())
        },
        ffi::btck_precomputed_transaction_data_destroy,
        "precomputed transaction data",
    )?;
    let mut status = 0u8;
    // SAFETY: every handle is live; `status` is a valid out-pointer
    let ok = unsafe {
        ffi::btck_script_pubkey_verify(
            spk.ptr,
            amount,
            tx.ptr,
            txdata.ptr,
            input_index,
            flags,
            &mut status,
        )
    };
    drop(txdata);
    drop(spent);
    drop(spent_scripts);
    if status != 0 {
        return Err(KernelError::Status(status));
    }
    Ok(ok == 1)
}

/// BIP-340's tagged hash.
fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag = Sha256::digest(tag.as_bytes());
    Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(msg)
        .finalize()
        .into()
}

/// The canonical transaction's prevout txid for the mint at `domain`.
pub fn spend_prevout(domain: &str) -> [u8; 32] {
    tagged_hash("LNURLcash/mint", domain.to_ascii_lowercase().as_bytes())
}

/// `OP_1 <Q>`: the spent output's scriptPubKey.
pub fn p2tr_script(output_key: &[u8; 32]) -> [u8; 34] {
    let mut script = [0u8; 34];
    script[0] = 0x51;
    script[1] = 0x20;
    script[2..].copy_from_slice(output_key);
    script
}

fn compact_size(n: usize, out: &mut Vec<u8>) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
}

/// The canonical spend transaction for `domain`, with `stack` as input 0's
/// witness: `[sig]` for a key path, `[*witness, script, control_block]` for
/// a script path.
pub fn build_spend_tx(domain: &str, stack: &[&[u8]], locktime: u32, sequence: u32) -> Vec<u8> {
    let mut tx = Vec::with_capacity(96 + stack.iter().map(|i| i.len() + 3).sum::<usize>());
    tx.extend_from_slice(&TX_VERSION.to_le_bytes());
    tx.extend_from_slice(&[0x00, 0x01]); // segwit marker and flag
    tx.push(1);
    tx.extend_from_slice(&spend_prevout(domain));
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.push(0); // empty scriptSig
    tx.extend_from_slice(&sequence.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&0i64.to_le_bytes());
    tx.push(0); // empty scriptPubKey
    compact_size(stack.len(), &mut tx);
    for item in stack {
        compact_size(item.len(), &mut tx);
        tx.extend_from_slice(item);
    }
    tx.extend_from_slice(&locktime.to_le_bytes());
    tx
}

/// Does `stack` spend the note `output_key` at `domain`, under the claimed
/// locktime and sequence? Pure: whether that time claim is due is the
/// mint's clock, never checked here.
pub fn verify_witness(
    output_key: &[u8; 32],
    domain: &str,
    stack: &[&[u8]],
    locktime: u32,
    sequence: u32,
) -> Result<bool, KernelError> {
    if domain.is_empty() {
        return Err(KernelError::Invalid("a spend is bound to a domain"));
    }
    if stack.is_empty() {
        return Ok(false);
    }
    let spk = p2tr_script(output_key);
    let tx = build_spend_tx(domain, stack, locktime, sequence);
    verify_input(&spk, 0, &tx, &[(&spk, 0)], 0, flags::ALL)
}

/// A key-path spend: a BIP-340 signature by `Q` itself.
pub fn verify_key_path(
    output_key: &[u8; 32],
    domain: &str,
    signature: &[u8],
) -> Result<bool, KernelError> {
    verify_witness(
        output_key,
        domain,
        &[signature],
        KEY_PATH_LOCKTIME,
        KEY_PATH_SEQUENCE,
    )
}

/// A script-path spend: `witness` (bottom of the stack first), then the leaf
/// `script` and its `control_block`.
pub fn verify_script_path(
    output_key: &[u8; 32],
    domain: &str,
    script: &[u8],
    control_block: &[u8],
    witness: &[&[u8]],
    locktime: u32,
    sequence: u32,
) -> Result<bool, KernelError> {
    let mut stack = witness.to_vec();
    stack.push(script);
    stack.push(control_block);
    verify_witness(output_key, domain, &stack, locktime, sequence)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn core_vectors() -> Value {
        serde_json::from_str(include_str!(
            "../vendor/bitcoin/src/test/data/bip341_wallet_vectors.json"
        ))
        .unwrap()
    }

    fn unhex(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    /// Core's own BIP-341 vectors, before any of this crate's logic: if
    /// these fail, the binding is wired wrong.
    #[test]
    fn core_signed_taproot_transaction_verifies_on_every_input() {
        let v = &core_vectors()["keyPathSpending"][0];
        let tx = unhex(&v["auxiliary"]["fullySignedTx"]);
        let utxos: Vec<(Vec<u8>, i64)> = v["given"]["utxosSpent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| (unhex(&u["scriptPubKey"]), u["amountSats"].as_i64().unwrap()))
            .collect();
        let spent: Vec<(&[u8], i64)> = utxos.iter().map(|(s, a)| (s.as_slice(), *a)).collect();
        assert_eq!(spent.len(), 9);
        for (i, (script, amount)) in spent.iter().enumerate() {
            assert!(
                verify_input(script, *amount, &tx, &spent, i as u32, flags::ALL).unwrap(),
                "Core's own signed input {i} was rejected"
            );
        }
        // a wrong amount changes every taproot sighash
        let mut wrong = spent.clone();
        wrong[0].1 += 1;
        assert!(!verify_input(wrong[0].0, wrong[0].1, &tx, &wrong, 0, flags::ALL).unwrap());
    }

    #[test]
    fn garbage_is_an_error_not_a_verdict() {
        let spk = p2tr_script(&[1; 32]);
        assert_eq!(
            verify_input(&spk, 0, &[0xde, 0xad], &[(&spk, 0)], 0, flags::ALL),
            Err(KernelError::Rejected("transaction"))
        );
        assert!(verify_witness(&[1; 32], "", &[&[0; 64]], 0, 0).is_err());
    }

    /// OP_SHA256 <h> OP_EQUAL under BIP-341's NUMS key, preimage 00..1f:
    /// LUD-25's bearer_note vector.
    #[test]
    fn lud25_bearer_note() {
        let preimage: Vec<u8> = (0u8..32).collect();
        let leaf =
            hex::decode("a820630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd87")
                .unwrap();
        let control =
            hex::decode("c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
                .unwrap();
        let q: [u8; 32] =
            hex::decode("d18b619687343df2fc7a47e1daf25260b909bb563fb4b4b11e59e2bd64880982")
                .unwrap()
                .try_into()
                .unwrap();
        let open = |witness: &[u8]| {
            verify_script_path(
                &q,
                "mint.example",
                &leaf,
                &control,
                &[witness],
                0,
                KEY_PATH_SEQUENCE,
            )
            .unwrap()
        };
        assert!(open(&preimage));
        assert!(!open(&[0; 32]));
    }

    /// LUD-25's key_path_spend vector: the exact transaction, and Core's verdict.
    #[test]
    fn lud25_key_path_spend() {
        let q: [u8; 32] =
            hex::decode("690ac33892c64aa53874b0066ab1332f0ef45cb7c0e017eae0828916f52aa99f")
                .unwrap()
                .try_into()
                .unwrap();
        let sig = hex::decode("fc3491f1c6bca73dcd76b38fc6b7a82aef0f1fa67212ceb7d7f64dbc41c8bfe77e0db6077624bf117badb65efe0445e382ac9f4cd582f7a5cc366c7aeb4580d4").unwrap();
        assert_eq!(
            hex::encode(spend_prevout("mint.example")),
            "d5ac2de3423432e37713bcb133cfea7938ff6b2f8ea4174dfcec84bea705d6b2"
        );
        assert_eq!(
            hex::encode(build_spend_tx("mint.example", &[&sig], KEY_PATH_LOCKTIME, KEY_PATH_SEQUENCE)),
            "02000000000101d5ac2de3423432e37713bcb133cfea7938ff6b2f8ea4174dfcec84bea705d6b20000000000ffffffff010000000000000000000140fc3491f1c6bca73dcd76b38fc6b7a82aef0f1fa67212ceb7d7f64dbc41c8bfe77e0db6077624bf117badb65efe0445e382ac9f4cd582f7a5cc366c7aeb4580d400000000"
        );
        assert!(verify_key_path(&q, "mint.example", &sig).unwrap());
        // bound to its domain: nowhere else
        assert!(!verify_key_path(&q, "other.example", &sig).unwrap());
    }
}
