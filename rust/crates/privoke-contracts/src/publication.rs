//! The signed publication statement of a V3 version (stage V3-R2 of the routine-training plan).
//!
//! param-update signs one statement per published version of a model with a dedicated Ed25519 publication key; a client that
//! compiles the public keys by `key_id` admits a trained version only when the statement verifies (stage V3-R4a). The
//! statement attests param-update's admission of the version, nothing the trainer says about itself.
//!
//! # Format
//!
//! The statement is the canonical JSON object `{tag, key_id, model_id, manifest_sha, parent, original, sequence}` and the
//! signature is Ed25519 over exactly those canonical bytes (so the tag is the domain separation: a signature over anything
//! else the key ever signs cannot be replayed as a statement). The wire form is the canonical JSON object of those seven
//! fields plus `signature` (128 lowercase hexadecimal characters), which is what `ModelPackageResponse.publication_statement`
//! carries. `parent` and `original` are the manifest's own fields: empty for an ORIGINAL, a SHA-256 otherwise. `sequence` is
//! per model, monotonic and at least 1.
//!
//! The format is new in V3-R2 and has no Python oracle (the Python client is frozen); `tests/fixtures/v3_signed_chain` holds
//! the shared deterministic fixtures every consumer replays.

use std::collections::BTreeMap;

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::canonical::{self, Variant};
use crate::json::Value;
use crate::v3::{is_sha_text, parse};

/// The domain tag every statement carries and every signature covers.
pub const STATEMENT_TAG: &str = "privoke-v3-publication-v1";
/// The largest admitted statement on the wire.
pub const MAX_STATEMENT_BYTES: usize = 4096;

/// Why a statement was not admitted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicationError {
    /// The wire bytes are not a canonical statement of exactly the admitted fields.
    #[error("malformed publication statement: {0}")]
    Malformed(&'static str),
    /// The statement names a `key_id` the key set does not hold.
    #[error("publication statement names an unknown key id")]
    UnknownKey,
    /// The signature does not verify under the named key.
    #[error("publication statement signature does not verify")]
    BadSignature,
    /// The key material is not usable.
    #[error("publication key is not usable")]
    BadKey,
}

/// What the publication key attests about one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The key that signs (and the client looks up).
    pub key_id: String,
    /// `privoke-v3-<tier>`.
    pub model_id: String,
    /// The SHA-256 of the published manifest.
    pub manifest_sha: String,
    /// The manifest's `parent` (empty for an ORIGINAL).
    pub parent: String,
    /// The manifest's `original` (empty for an ORIGINAL).
    pub original: String,
    /// The per-model monotonic sequence, at least 1.
    pub sequence: u64,
}

fn text(value: &str) -> Value {
    Value::String(value.to_string())
}

impl Statement {
    fn fields(&self) -> BTreeMap<String, Value> {
        [
            ("tag", text(STATEMENT_TAG)),
            ("key_id", text(&self.key_id)),
            ("model_id", text(&self.model_id)),
            ("manifest_sha", text(&self.manifest_sha)),
            ("parent", text(&self.parent)),
            ("original", text(&self.original)),
            ("sequence", Value::Int(self.sequence.to_string())),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
    }

    /// The canonical bytes the signature covers.
    pub fn message(&self) -> Vec<u8> {
        // A map of strings and one integer always has a canonical form.
        canonical::to_bytes(&Value::Object(self.fields()), Variant::Utf8Lf).unwrap_or_default()
    }

    /// The wire form with `signature` attached.
    pub fn encode(&self, signature: &[u8; 64]) -> Vec<u8> {
        let mut fields = self.fields();
        fields.insert("signature".to_string(), text(&hex(signature)));
        canonical::to_bytes(&Value::Object(fields), Variant::Utf8Lf).unwrap_or_default()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok()).collect()
}

/// The public key of a 32-byte seed.
pub fn public_key(seed: &[u8; 32]) -> Result<[u8; 32], PublicationError> {
    let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| PublicationError::BadKey)?;
    pair.public_key().as_ref().try_into().map_err(|_| PublicationError::BadKey)
}

/// Sign `statement` with the key of `seed`; the result is the wire form.
pub fn sign(seed: &[u8; 32], statement: &Statement) -> Result<Vec<u8>, PublicationError> {
    let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| PublicationError::BadKey)?;
    let signature: [u8; 64] = pair.sign(&statement.message()).as_ref().try_into().map_err(|_| PublicationError::BadKey)?;
    Ok(statement.encode(&signature))
}

/// The public keys a verifier trusts, by `key_id`. A key-rotation overlap is a set of two.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySet {
    keys: BTreeMap<String, [u8; 32]>,
}

impl KeySet {
    /// An empty set (admits nothing).
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `public` under `key_id`.
    #[must_use]
    pub fn with(mut self, key_id: &str, public: [u8; 32]) -> Self {
        self.keys.insert(key_id.to_string(), public);
        self
    }

    /// Trust a key given as 64 lowercase hexadecimal characters.
    pub fn with_hex(self, key_id: &str, public: &str) -> Result<Self, PublicationError> {
        let bytes: [u8; 32] = unhex(public).and_then(|bytes| bytes.try_into().ok()).ok_or(PublicationError::BadKey)?;
        Ok(self.with(key_id, bytes))
    }

    /// Whether the set holds `key_id`.
    pub fn contains(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    /// The key ids, sorted.
    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.keys().map(String::as_str).collect()
    }
}

fn string<'a>(map: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a str> {
    match map.get(key) {
        Some(Value::String(text)) => Some(text),
        _ => None,
    }
}

/// Parse the wire form without checking the signature: the statement and its signature bytes.
pub fn decode(encoded: &[u8]) -> Result<(Statement, [u8; 64]), PublicationError> {
    let malformed = PublicationError::Malformed;
    let document = parse(encoded, MAX_STATEMENT_BYTES).map_err(|_| malformed("not canonical JSON"))?;
    let Value::Object(map) = &document else { return Err(malformed("not an object")) };
    let expected = ["key_id", "manifest_sha", "model_id", "original", "parent", "sequence", "signature", "tag"];
    if map.keys().map(String::as_str).collect::<Vec<_>>() != expected {
        return Err(malformed("fields"));
    }
    if string(map, "tag") != Some(STATEMENT_TAG) {
        return Err(malformed("tag"));
    }
    let field = |key: &'static str| string(map, key).map(str::to_string).ok_or(malformed(key));
    let (key_id, model_id) = (field("key_id")?, field("model_id")?);
    let (manifest_sha, parent, original) = (field("manifest_sha")?, field("parent")?, field("original")?);
    let tier = model_id.strip_prefix("privoke-v3-").unwrap_or_default();
    if key_id.is_empty() || key_id.len() > 64 || !crate::v3::TIERS.iter().any(|candidate| candidate.name == tier) {
        return Err(malformed("key_id or model_id"));
    }
    if !is_sha_text(&manifest_sha) || [&parent, &original].iter().any(|value| !value.is_empty() && !is_sha_text(value)) {
        return Err(malformed("digest"));
    }
    let sequence = match map.get("sequence") {
        Some(Value::Int(digits)) => digits.parse::<u64>().ok().filter(|sequence| *sequence >= 1),
        _ => None,
    }
    .ok_or(malformed("sequence"))?;
    let signature: [u8; 64] =
        string(map, "signature").and_then(unhex).and_then(|bytes| bytes.try_into().ok()).ok_or(malformed("signature"))?;
    Ok((Statement { key_id, model_id, manifest_sha, parent, original, sequence }, signature))
}

/// Admit a statement: well formed, a known `key_id`, and a signature that verifies over its canonical message.
pub fn verify(keys: &KeySet, encoded: &[u8]) -> Result<Statement, PublicationError> {
    let (statement, signature) = decode(encoded)?;
    let public = keys.keys.get(&statement.key_id).ok_or(PublicationError::UnknownKey)?;
    UnparsedPublicKey::new(&ED25519, public).verify(&statement.message(), &signature).map_err(|_| PublicationError::BadSignature)?;
    Ok(statement)
}

/// Deterministic keys for tests and fixtures. They exist only behind the `test-keys` cargo feature and are never compiled into
/// a client or a service build.
#[cfg(feature = "test-keys")]
pub mod test_keys {
    use sha2::{Digest, Sha256};

    use super::{KeySet, public_key};

    /// The `key_id` of the primary test key.
    pub const PRIMARY_ID: &str = "test-publication-1";
    /// The `key_id` of the second test key (the rotation overlap).
    pub const SECONDARY_ID: &str = "test-publication-2";

    /// The seed of a test key: the SHA-256 of a fixed label.
    pub fn seed(key_id: &str) -> [u8; 32] {
        Sha256::digest(format!("privoke-v3-test-key\n{key_id}\n").as_bytes()).into()
    }

    /// The set holding both test keys.
    pub fn key_set() -> KeySet {
        let both = [PRIMARY_ID, SECONDARY_ID];
        both.iter().fold(KeySet::new(), |keys, id| keys.with(id, public_key(&seed(id)).unwrap_or([0; 32])))
    }

    /// The set holding only the primary test key.
    pub fn primary_only() -> KeySet {
        KeySet::new().with(PRIMARY_ID, public_key(&seed(PRIMARY_ID)).unwrap_or([0; 32]))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// RFC 8032 section 7.1, test 1 (empty message).
    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIGNATURE: &str =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    fn statement() -> Statement {
        Statement {
            key_id: "k".to_string(),
            model_id: "privoke-v3-efficient".to_string(),
            manifest_sha: "a".repeat(64),
            parent: "b".repeat(64),
            original: "c".repeat(64),
            sequence: 3,
        }
    }

    fn seed() -> [u8; 32] {
        unhex(SEED).unwrap().try_into().unwrap()
    }

    #[test]
    fn the_rfc_8032_vector_pins_the_key_and_signature_algorithm() {
        assert_eq!(hex(&public_key(&seed()).unwrap()), PUBLIC);
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed()).unwrap();
        assert_eq!(hex(pair.sign(b"").as_ref()), SIGNATURE);
    }

    #[test]
    fn a_signed_statement_round_trips_and_every_change_is_refused() {
        let keys = KeySet::new().with("k", public_key(&seed()).unwrap());
        let wire = sign(&seed(), &statement()).unwrap();
        assert_eq!(verify(&keys, &wire).unwrap(), statement());
        assert_eq!(sign(&seed(), &statement()).unwrap(), wire, "Ed25519 signatures are deterministic");
        // Another key id, an unknown one, and a flipped signature.
        assert_eq!(verify(&KeySet::new(), &wire).unwrap_err(), PublicationError::UnknownKey);
        let other = KeySet::new().with("k", public_key(&[7; 32]).unwrap());
        assert_eq!(verify(&other, &wire).unwrap_err(), PublicationError::BadSignature);
        let mut changed = statement();
        changed.sequence = 4;
        let text = String::from_utf8(wire.clone()).unwrap();
        let tampered = text.replace("\"sequence\":3", "\"sequence\":4");
        assert_ne!(tampered, text);
        assert_eq!(verify(&keys, tampered.as_bytes()).unwrap_err(), PublicationError::BadSignature);
        // Not canonical, extra fields, a wrong tag, a zero sequence and a short digest are malformed.
        let spaced = text.replace(",\"manifest_sha\"", ", \"manifest_sha\"");
        assert!(matches!(verify(&keys, spaced.as_bytes()), Err(PublicationError::Malformed(_))));
        let extra = text.replace("\"tag\"", "\"extra\":1,\"tag\"");
        assert!(matches!(verify(&keys, extra.as_bytes()), Err(PublicationError::Malformed(_))));
        let tag = text.replace(STATEMENT_TAG, "privoke-v3-publication-v0");
        assert!(matches!(verify(&keys, tag.as_bytes()), Err(PublicationError::Malformed(_))));
        let zero = text.replace("\"sequence\":3", "\"sequence\":0");
        assert!(matches!(verify(&keys, zero.as_bytes()), Err(PublicationError::Malformed(_))));
        let short = text.replace(&"a".repeat(64), "aa");
        assert!(matches!(verify(&keys, short.as_bytes()), Err(PublicationError::Malformed(_))));
        assert!(matches!(verify(&keys, b"{}\n"), Err(PublicationError::Malformed(_))));
        assert!(changed.message() != statement().message());
    }

    #[test]
    fn an_original_statement_has_empty_lineage_and_a_key_set_holds_a_rotation_overlap() {
        let mut original = statement();
        original.parent.clear();
        original.original.clear();
        let wire = sign(&seed(), &original).unwrap();
        let keys = KeySet::new().with("k", public_key(&seed()).unwrap()).with("next", public_key(&[9; 32]).unwrap());
        assert_eq!(keys.key_ids(), vec!["k", "next"]);
        assert!(keys.contains("next"));
        assert_eq!(verify(&keys, &wire).unwrap(), original);
        assert_eq!(KeySet::new().with_hex("k", PUBLIC).unwrap(), KeySet::new().with("k", public_key(&seed()).unwrap()));
        assert!(KeySet::new().with_hex("k", "zz").is_err());
    }
}
