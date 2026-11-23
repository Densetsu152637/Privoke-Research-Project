//! Stage V3-R3: model-streaming serves the trained V3 versions that param-update published.
//!
//! The authority is a SQLite catalog laid out as `rust/services/param-update/src/v3_store/store.rs` creates it; the published
//! tree is laid out as `docs/runtime/v3-publication.md` describes. The toy packages are small real files whose digests the
//! manifests name, and the statements are signed by the shared deterministic test keys (the same keys as the signed-chain
//! fixtures of `privoke-contracts`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::proto::v1::{ModelAssetRequest, ModelPackageResponse, ModelParametersRequest};
use privoke_contracts::publication::{self, Statement, test_keys};
use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::config::ServiceConfig;
use privoke_model_streaming::published::Published;
use privoke_model_streaming::releases::{ASSET_KEYS, STANDARD_IDS, StandardReleases, V3_ARCHITECTURE};
use privoke_model_streaming::service::ModelService;
use rusqlite::{Connection, params};
use tonic::Code;

const BALANCED: &str = "privoke-v3-balanced";
const EFFICIENT: &str = "privoke-v3-efficient";

/// The DDL of `CheckpointStore::open`.
const DDL: &str = "CREATE TABLE IF NOT EXISTS current(model TEXT PRIMARY KEY, manifest TEXT NOT NULL);\
     CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, payload BLOB NOT NULL);\
     CREATE TABLE IF NOT EXISTS versions(model TEXT NOT NULL, manifest TEXT NOT NULL, PRIMARY KEY(model, manifest));\
     CREATE TABLE IF NOT EXISTS publications(model TEXT NOT NULL, sequence INTEGER NOT NULL, manifest TEXT NOT NULL, \
     key_id TEXT NOT NULL, statement BLOB NOT NULL, request_id TEXT NOT NULL, PRIMARY KEY(model, sequence));";

/// One toy package: a manifest and the four assets it names.
struct Package {
    manifest: Vec<u8>,
    sha: String,
    assets: Vec<(&'static str, Vec<u8>)>,
}

fn package(id: &str, label: &str, parent: &str, original: &str) -> Package {
    let assets: Vec<(&'static str, Vec<u8>)> =
        ASSET_KEYS.iter().map(|(name, _)| (*name, format!("{id} {label} {name} bytes, long enough to be a file").into_bytes())).collect();
    let digest = |name: &str| sha256_hex(&assets.iter().find(|(candidate, _)| *candidate == name).unwrap().1);
    let manifest = format!(
        "{{\"architecture\":\"{V3_ARCHITECTURE}\",\"blob\":\"{}\",\"config\":\"{}\",\"evidence\":\"{}\",\"label\":\"{label}\",\
         \"model_id\":\"{id}\",\"original\":\"{original}\",\"parent\":\"{parent}\",\"vocab\":\"{}\"}}\n",
        digest("model.safetensors"),
        digest("config.json"),
        digest("evidence.json"),
        digest("vocab.txt"),
    )
    .into_bytes();
    Package { sha: sha256_hex(&manifest), manifest, assets }
}

fn bytes_of<'a>(package: &'a Package, name: &str) -> &'a Vec<u8> {
    &package.assets.iter().find(|(candidate, _)| *candidate == name).unwrap().1
}

fn write_package(directory: &Path, package: &Package) {
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(directory.join("manifest.json"), &package.manifest).unwrap();
    for (name, bytes) in &package.assets {
        std::fs::write(directory.join(name), bytes).unwrap();
    }
}

fn statement(id: &str, package: &Package, parent: &str, original: &str, sequence: u64) -> Vec<u8> {
    let statement = Statement {
        key_id: test_keys::PRIMARY_ID.to_string(),
        model_id: id.to_string(),
        manifest_sha: package.sha.clone(),
        parent: parent.to_string(),
        original: original.to_string(),
        sequence,
    };
    publication::sign(&test_keys::seed(test_keys::PRIMARY_ID), &statement).unwrap()
}

/// A deployment in a temporary directory: pinned ORIGINALs, an empty published root and an empty store directory.
struct World {
    directory: tempfile::TempDir,
    originals: BTreeMap<&'static str, Package>,
}

impl World {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut originals = BTreeMap::new();
        for id in STANDARD_IDS {
            let original = package(id, "original", "", "");
            write_package(&directory.path().join("releases").join(id), &original);
            originals.insert(id, original);
        }
        std::fs::create_dir_all(directory.path().join("published")).unwrap();
        std::fs::create_dir_all(directory.path().join("store")).unwrap();
        Self { directory, originals }
    }

    fn published_root(&self) -> PathBuf {
        self.directory.path().join("published")
    }

    fn store(&self) -> PathBuf {
        self.directory.path().join("store")
    }

    fn pin(&self, id: &str) -> &str {
        &self.originals[id].sha
    }

    fn service(&self) -> ModelService {
        let pins = self.originals.iter().map(|(id, original)| ((*id).to_string(), original.sha.clone())).collect();
        let mut catalog = Catalog::from_paths(BALANCED, BTreeMap::new());
        catalog.releases = Some(StandardReleases::open_with_pins(&self.directory.path().join("releases"), pins).unwrap());
        catalog.published = Some(Published::open(&self.published_root(), &self.store()).unwrap());
        ModelService::new(Arc::new(catalog))
    }

    fn database(&self) -> Connection {
        let database = Connection::open(self.store().join("catalog.sqlite")).unwrap();
        database.execute_batch(DDL).unwrap();
        database
    }

    /// The store serves the pinned ORIGINAL of `id` and nothing is published (a store that only knows its ORIGINALs).
    fn serve_originals(&self, database: &Connection) {
        for id in STANDARD_IDS {
            database.execute("INSERT OR REPLACE INTO current(model, manifest) VALUES (?1, ?2)", params![id, self.pin(id)]).unwrap();
            database.execute("INSERT OR IGNORE INTO versions(model, manifest) VALUES (?1, ?2)", params![id, self.pin(id)]).unwrap();
        }
    }

    /// What param-update does after a commit: write the published directory, record the publication, swap `current`.
    fn publish(&self, database: &Connection, id: &str, package: &Package, statement: &[u8], sequence: u64) {
        let directory = self.published_root().join(id).join(&package.sha);
        write_package(&directory, package);
        std::fs::write(directory.join("statement.json"), statement).unwrap();
        record(database, id, package, statement, sequence);
    }
}

fn record(database: &Connection, id: &str, package: &Package, statement: &[u8], sequence: u64) {
    database
        .execute(
            "INSERT INTO publications(model, sequence, manifest, key_id, statement, request_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, i64::try_from(sequence).unwrap(), package.sha, test_keys::PRIMARY_ID, statement, format!("request-{sequence}")],
        )
        .unwrap();
    database.execute("INSERT OR IGNORE INTO versions(model, manifest) VALUES (?1, ?2)", params![id, package.sha]).unwrap();
    database.execute("INSERT OR REPLACE INTO current(model, manifest) VALUES (?1, ?2)", params![id, package.sha]).unwrap();
}

fn package_request(model: &str) -> ModelParametersRequest {
    ModelParametersRequest { consumer_id: "unit".into(), model_id: model.into() }
}

fn asset_request(model: &str, sha: &str, asset: &str) -> ModelAssetRequest {
    ModelAssetRequest { consumer_id: "unit".into(), model_id: model.into(), manifest_sha256: sha.into(), asset_name: asset.into() }
}

/// What `StreamModelAsset` sends for one asset, after the request check.
fn fetch(service: &ModelService, model: &str, sha: &str, asset: &str) -> Result<Vec<u8>, tonic::Status> {
    let request = asset_request(model, sha, asset);
    service.check_asset_request(&request)?;
    let mut bytes = Vec::new();
    service.stream_asset_core(&request, |chunk| {
        assert_eq!((chunk.model_id.as_str(), chunk.manifest_sha256.as_str()), (model, sha));
        assert_eq!(chunk.offset, bytes.len() as u64);
        bytes.extend_from_slice(&chunk.data);
        true
    })?;
    Ok(bytes)
}

fn assert_serves(response: &ModelPackageResponse, id: &str, package: &Package, statement: &[u8]) {
    assert_eq!(response.model_id, id);
    assert_eq!(response.architecture, V3_ARCHITECTURE);
    assert_eq!(response.manifest_sha256, package.sha);
    assert_eq!(response.manifest_json, package.manifest);
    assert_eq!(response.publication_statement, statement);
    let names: Vec<&str> = response.assets.iter().map(|asset| asset.name.as_str()).collect();
    assert_eq!(names, ["config.json", "evidence.json", "model.safetensors", "vocab.txt"]);
    for asset in &response.assets {
        let bytes = &package.assets.iter().find(|(name, _)| *name == asset.name).unwrap().1;
        assert_eq!((asset.sha256.clone(), asset.size_bytes), (sha256_hex(bytes), bytes.len() as u64));
    }
}

#[test]
fn nothing_published_serves_the_pinned_original() {
    let world = World::new();
    let service = world.service();
    // No catalog file yet.
    for id in STANDARD_IDS {
        let response = service.get_model_package_core(&package_request(id)).unwrap();
        assert_serves(&response, id, &world.originals[id], b"");
    }
    // A store that holds only its ORIGINALs, with versions but no publications, and an unsigned later version.
    let database = world.database();
    world.serve_originals(&database);
    let response = service.get_model_package_core(&package_request(EFFICIENT)).unwrap();
    assert_serves(&response, EFFICIENT, &world.originals[EFFICIENT], b"");
    let unsigned = package(EFFICIENT, "unsigned", world.pin(EFFICIENT), world.pin(EFFICIENT));
    write_package(&world.published_root().join(EFFICIENT).join(&unsigned.sha), &unsigned);
    database.execute("INSERT INTO versions(model, manifest) VALUES (?1, ?2)", params![EFFICIENT, unsigned.sha]).unwrap();
    database.execute("UPDATE current SET manifest=?2 WHERE model=?1", params![EFFICIENT, unsigned.sha]).unwrap();
    let response = service.get_model_package_core(&package_request(EFFICIENT)).unwrap();
    assert_eq!(response.manifest_sha256, world.pin(EFFICIENT), "a version that was never published must not be served");
    let latest = service.get_model_package_core(&package_request("latest")).unwrap();
    assert_eq!(latest.model_id, BALANCED);
    assert!(latest.publication_statement.is_empty());
}

#[test]
fn a_published_candidate_is_served_with_its_statement_and_its_bytes() {
    let world = World::new();
    let service = world.service();
    let database = world.database();
    world.serve_originals(&database);
    let original = &world.originals[EFFICIENT];
    let heads = package(EFFICIENT, "heads", &original.sha, &original.sha);
    let signed = statement(EFFICIENT, &heads, &original.sha, &original.sha, 1);
    world.publish(&database, EFFICIENT, &heads, &signed, 1);

    let response = service.get_model_package_core(&package_request(EFFICIENT)).unwrap();
    assert_serves(&response, EFFICIENT, &heads, &signed);
    let (decoded, _) = publication::decode(&response.publication_statement).unwrap();
    assert_eq!((decoded.sequence, decoded.manifest_sha.as_str()), (1, heads.sha.as_str()));
    for (name, bytes) in &heads.assets {
        assert_eq!(&fetch(&service, EFFICIENT, &heads.sha, name).unwrap(), bytes, "{name}");
    }
    // The other tiers are untouched, and `latest` still resolves to the balanced model.
    let balanced = service.get_model_package_core(&package_request("latest")).unwrap();
    assert_serves(&balanced, BALANCED, &world.originals[BALANCED], b"");
    // A newer publication replaces the served one at the next request; the older one stays fetchable (rollback history).
    let full = package(EFFICIENT, "full", &heads.sha, &original.sha);
    let signed_full = statement(EFFICIENT, &full, &heads.sha, &original.sha, 2);
    world.publish(&database, EFFICIENT, &full, &signed_full, 2);
    let response = service.get_model_package_core(&package_request(EFFICIENT)).unwrap();
    assert_serves(&response, EFFICIENT, &full, &signed_full);
    assert_eq!(&fetch(&service, EFFICIENT, &heads.sha, "config.json").unwrap(), bytes_of(&heads, "config.json"));
}

#[test]
fn the_original_stays_fetchable_by_pin_after_publication() {
    let world = World::new();
    let service = world.service();
    let database = world.database();
    world.serve_originals(&database);
    let original = &world.originals[EFFICIENT];
    let heads = package(EFFICIENT, "heads", &original.sha, &original.sha);
    let signed = statement(EFFICIENT, &heads, &original.sha, &original.sha, 1);
    world.publish(&database, EFFICIENT, &heads, &signed, 1);

    // By pin: the ORIGINAL, without a statement, for every tier, and its assets.
    for id in STANDARD_IDS {
        let response = service.get_model_package_core(&package_request(&format!("{id}@{}", world.pin(id)))).unwrap();
        assert_serves(&response, id, &world.originals[id], b"");
        for (name, bytes) in &world.originals[id].assets {
            assert_eq!(&fetch(&service, id, world.pin(id), name).unwrap(), bytes, "{id} {name}");
        }
    }
    // By manifest: the published version with its statement.
    let response = service.get_model_package_core(&package_request(&format!("{EFFICIENT}@{}", heads.sha))).unwrap();
    assert_serves(&response, EFFICIENT, &heads, &signed);

    // A signed rollback to the ORIGINAL: the plain id serves the pinned bytes with the rollback's statement.
    let rollback = statement(EFFICIENT, original, "", "", 2);
    record(&database, EFFICIENT, original, &rollback, 2);
    let response = service.get_model_package_core(&package_request(EFFICIENT)).unwrap();
    assert_serves(&response, EFFICIENT, original, &rollback);
    // The rolled-back version stays in the history and is still fetchable.
    assert_eq!(&fetch(&service, EFFICIENT, &heads.sha, "vocab.txt").unwrap(), bytes_of(&heads, "vocab.txt"));
    // The pin-addressed ORIGINAL is still statement-free.
    let response = service.get_model_package_core(&package_request(&format!("{EFFICIENT}@{}", original.sha))).unwrap();
    assert_serves(&response, EFFICIENT, original, b"");
}

#[test]
fn an_unpublished_sha_or_an_unreferenced_directory_is_invalid_argument() {
    let world = World::new();
    let service = world.service();
    let database = world.database();
    world.serve_originals(&database);
    let original = &world.originals[EFFICIENT];
    let heads = package(EFFICIENT, "heads", &original.sha, &original.sha);
    let signed = statement(EFFICIENT, &heads, &original.sha, &original.sha, 1);
    world.publish(&database, EFFICIENT, &heads, &signed, 1);

    // A complete, correct directory that the authority does not reference.
    let stray = package(EFFICIENT, "stray", &heads.sha, &original.sha);
    write_package(&world.published_root().join(EFFICIENT).join(&stray.sha), &stray);
    std::fs::write(world.published_root().join(EFFICIENT).join(&stray.sha).join("statement.json"), &signed).unwrap();
    // A version the store served that was never signed (in `versions`, not in `publications`).
    let unsigned = package(EFFICIENT, "unsigned", &heads.sha, &original.sha);
    write_package(&world.published_root().join(EFFICIENT).join(&unsigned.sha), &unsigned);
    database.execute("INSERT INTO versions(model, manifest) VALUES (?1, ?2)", params![EFFICIENT, unsigned.sha]).unwrap();
    // A version published for another model, asked for under this one.
    let other = package(BALANCED, "heads", world.pin(BALANCED), world.pin(BALANCED));
    world.publish(&database, BALANCED, &other, &statement(BALANCED, &other, world.pin(BALANCED), world.pin(BALANCED), 1), 1);
    // An unknown manifest.
    let unknown = "0".repeat(64);

    for sha in [&stray.sha, &unsigned.sha, &other.sha, &unknown] {
        let error = service.get_model_package_core(&package_request(&format!("{EFFICIENT}@{sha}"))).unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument, "package for {sha}");
        for asset in ["manifest.json", "model.safetensors"] {
            let error = service.check_asset_request(&asset_request(EFFICIENT, sha, asset)).unwrap_err();
            assert_eq!(error.code(), Code::InvalidArgument, "asset {asset} for {sha}");
        }
        let error = fetch(&service, EFFICIENT, sha, "model.safetensors").unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument, "fetch for {sha}");
    }
    // The stream path decides for itself, even when the request check was skipped.
    let error = service.stream_asset_core(&asset_request(EFFICIENT, &stray.sha, "config.json"), |_| true).unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    // Shapes that are not manifests, and a pin on a model that is not a standard one.
    for model in [format!("{EFFICIENT}@"), format!("{EFFICIENT}@../{}", heads.sha), format!("{EFFICIENT}@{}", heads.sha.to_uppercase())] {
        let error = service.get_model_package_core(&package_request(&model)).unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument, "{model}");
    }
    let error = service.get_model_package_core(&package_request(&format!("privoke-balanced@{}", heads.sha))).unwrap_err();
    assert_eq!(error.code(), Code::NotFound);
    // The published, referenced version is still served, and its allowlist still applies.
    assert_eq!(&fetch(&service, EFFICIENT, &heads.sha, "config.json").unwrap(), bytes_of(&heads, "config.json"));
    let error = service.check_asset_request(&asset_request(EFFICIENT, &heads.sha, "../manifest.json")).unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
}

#[test]
fn the_authority_and_its_publications_must_agree() {
    let world = World::new();
    let service = world.service();
    let database = world.database();
    world.serve_originals(&database);
    let original = &world.originals[EFFICIENT];
    let heads = package(EFFICIENT, "heads", &original.sha, &original.sha);
    world.publish(&database, EFFICIENT, &heads, &statement(EFFICIENT, &heads, &original.sha, &original.sha, 1), 1);
    // A version swapped in without a signature while the model has publications: fail closed, not the old version.
    let swapped = package(EFFICIENT, "swapped", &heads.sha, &original.sha);
    write_package(&world.published_root().join(EFFICIENT).join(&swapped.sha), &swapped);
    database.execute("UPDATE current SET manifest=?2 WHERE model=?1", params![EFFICIENT, swapped.sha]).unwrap();
    let error = service.get_model_package_core(&package_request(EFFICIENT)).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    // The pinned and the published versions stay addressable by manifest.
    assert!(service.get_model_package_core(&package_request(&format!("{EFFICIENT}@{}", heads.sha))).is_ok());
    assert!(service.get_model_package_core(&package_request(&format!("{EFFICIENT}@{}", original.sha))).is_ok());
    // Another tier is unaffected.
    assert!(service.get_model_package_core(&package_request(BALANCED)).is_ok());

    // A statement that names another manifest is not served.
    let world = World::new();
    let service = world.service();
    let database = world.database();
    world.serve_originals(&database);
    let first = package(EFFICIENT, "first", world.pin(EFFICIENT), world.pin(EFFICIENT));
    let second = package(EFFICIENT, "second", world.pin(EFFICIENT), world.pin(EFFICIENT));
    let wrong = statement(EFFICIENT, &second, world.pin(EFFICIENT), world.pin(EFFICIENT), 1);
    world.publish(&database, EFFICIENT, &first, &wrong, 1);
    let error = service.get_model_package_core(&package_request(EFFICIENT)).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(
        service.get_model_package_core(&package_request(&format!("{EFFICIENT}@{}", first.sha))).unwrap_err().code(),
        Code::Unavailable
    );
}

#[test]
fn published_bytes_are_verified_against_the_manifest() {
    let world = World::new();
    let service = world.service();
    let database = world.database();
    world.serve_originals(&database);
    let original = &world.originals[EFFICIENT];
    let heads = package(EFFICIENT, "heads", &original.sha, &original.sha);
    let signed = statement(EFFICIENT, &heads, &original.sha, &original.sha, 1);
    world.publish(&database, EFFICIENT, &heads, &signed, 1);
    assert_serves(&service.get_model_package_core(&package_request(EFFICIENT)).unwrap(), EFFICIENT, &heads, &signed);

    // Same length, different bytes: the cached proof no longer matches the file, so it is hashed again.
    let weights = world.published_root().join(EFFICIENT).join(&heads.sha).join("model.safetensors");
    let mut tampered = std::fs::read(&weights).unwrap();
    tampered[0] ^= 0xff;
    std::fs::write(&weights, &tampered).unwrap();
    let error = fetch(&service, EFFICIENT, &heads.sha, "model.safetensors").unwrap_err();
    assert_eq!(error.code(), Code::DataLoss);
    // A manifest that is not the version's is refused.
    let manifest = world.published_root().join(EFFICIENT).join(&heads.sha).join("manifest.json");
    std::fs::write(&manifest, b"{}").unwrap();
    assert_eq!(service.get_model_package_core(&package_request(EFFICIENT)).unwrap_err().code(), Code::Unavailable);
    assert_eq!(fetch(&service, EFFICIENT, &heads.sha, "config.json").unwrap_err().code(), Code::Unavailable);
}

#[test]
fn a_symlinked_version_directory_is_not_served() {
    let world = World::new();
    let service = world.service();
    let database = world.database();
    world.serve_originals(&database);
    let original = &world.originals[EFFICIENT];
    let heads = package(EFFICIENT, "heads", &original.sha, &original.sha);
    let signed = statement(EFFICIENT, &heads, &original.sha, &original.sha, 1);
    world.publish(&database, EFFICIENT, &heads, &signed, 1);
    let directory = world.published_root().join(EFFICIENT).join(&heads.sha);
    let moved = world.published_root().join("moved");
    std::fs::rename(&directory, &moved).unwrap();
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(&moved, &directory).is_ok();
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_dir(&moved, &directory).is_ok();
    if !linked {
        eprintln!("directory links are unavailable on this platform; skipped");
        return;
    }
    assert_eq!(service.get_model_package_core(&package_request(EFFICIENT)).unwrap_err().code(), Code::Unavailable);
    assert_eq!(fetch(&service, EFFICIENT, &heads.sha, "config.json").unwrap_err().code(), Code::Unavailable);
}

/// The shared signed-chain fixtures: the authority built from `chain.json` is read as the publication order says.
#[test]
fn the_shared_signed_chain_is_read_as_published() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-contracts/tests/fixtures/v3_signed_chain/chain.json");
    let chain: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let model = chain["model_id"].as_str().unwrap();
    let sha_of = |label: &str| -> String {
        let entry = chain["manifests"].as_array().unwrap().iter().find(|entry| entry["label"] == label).unwrap();
        entry["manifest_sha"].as_str().unwrap().to_string()
    };

    let world = World::new();
    let database = world.database();
    let mut sequences = Vec::new();
    for entry in chain["chain"].as_array().unwrap() {
        let wire = entry["statement"].as_str().unwrap().as_bytes();
        let (decoded, _) = publication::decode(wire).unwrap();
        assert_eq!(decoded.manifest_sha, sha_of(entry["manifest"].as_str().unwrap()));
        database
            .execute(
                "INSERT INTO publications(model, sequence, manifest, key_id, statement, request_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![model, i64::try_from(decoded.sequence).unwrap(), decoded.manifest_sha, decoded.key_id, wire, "fixture"],
            )
            .unwrap();
        database.execute("INSERT OR REPLACE INTO current(model, manifest) VALUES (?1, ?2)", params![model, decoded.manifest_sha]).unwrap();
        sequences.push(decoded.sequence);
    }
    assert_eq!(sequences, [1, 2, 3, 4]);

    let published = Published::open(&world.published_root(), &world.store()).unwrap();
    let authority = published.authority(model).unwrap();
    assert_eq!(authority.current.as_deref(), Some(sha_of("heads-after-rollback").as_str()));
    assert_eq!(authority.latest().unwrap().sequence, 4);
    // The rollback to the ORIGINAL is a publication of the ORIGINAL's manifest, and the statements verify under the test keys.
    assert_eq!(authority.publication_of(&sha_of("original")).unwrap().sequence, 3);
    assert_eq!(authority.publication_of(&sha_of("heads")).unwrap().sequence, 1);
    assert_eq!(authority.publication_of(&sha_of("full")).unwrap().sequence, 2);
    for publication in &authority.publications {
        let statement = publication::verify(&test_keys::key_set(), &publication.statement).unwrap();
        assert_eq!((statement.sequence, statement.manifest_sha.as_str()), (publication.sequence, publication.manifest.as_str()));
    }
    // Manifests that were never published are not servable, whatever else the fixtures hold.
    for label in ["other-original", "wrong-original-heads"] {
        assert!(authority.publication_of(&sha_of(label)).is_none(), "{label}");
        assert!(!published.is_published(model, &sha_of(label)).unwrap(), "{label}");
    }
    assert!(published.is_published(model, &sha_of("full")).unwrap());
    // Another model has its own, empty, authority.
    assert_eq!(published.authority(BALANCED).unwrap(), privoke_model_streaming::published::Authority::default());
    assert!(published.authority("privoke-balanced").is_err());
}

#[test]
fn the_configuration_names_both_or_neither_location() {
    let lookup = |pairs: &'static [(&'static str, &'static str)]| {
        ServiceConfig::from_lookup(move |key| pairs.iter().find(|(name, _)| *name == key).map(|(_, value)| (*value).to_string()))
    };
    let none = lookup(&[]).unwrap();
    assert!(none.publish_root.is_none() && none.v3_store.is_none());
    let both = lookup(&[("V3_PUBLISH_ROOT", "/published"), ("V3_STORE", "/store")]).unwrap();
    assert_eq!((both.publish_root, both.v3_store), (Some("/published".into()), Some("/store".into())));
    assert!(lookup(&[("V3_PUBLISH_ROOT", "/published")]).is_err());
    assert!(lookup(&[("V3_STORE", "/store")]).is_err());
}

#[test]
fn a_missing_published_root_or_store_fails_at_open() {
    let world = World::new();
    assert!(Published::open(&world.directory.path().join("missing"), &world.store()).is_err());
    assert!(Published::open(&world.published_root(), &world.directory.path().join("missing")).is_err());
}
