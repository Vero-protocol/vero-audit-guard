//! OPA policy bundle loading and compilation.
//!
//! A bundle is a directory holding a `.manifest`, one or more `.rego` modules,
//! and an optional root `data.json`. [`BundleLoader::load`] reads that
//! directory, checks its contents against the manifest, and compiles the
//! modules into a [`CompiledBundle`] that can be evaluated at runtime.
//!
//! This module is observational. It loads, validates, and evaluates policy and
//! reports what a query returned; it never acts on the result and holds no
//! halt authority. Every failure is returned as a typed [`PolicyBundleError`]
//! and logged at `error` level, so a bundle that fails to load surfaces as an
//! alert rather than as an empty policy set that silently finds no violations.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use regorus::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MANIFEST_FILE: &str = ".manifest";
const DATA_FILE: &str = "data.json";
const REGO_EXTENSION: &str = "rego";
const PACKAGE_PREFIX: &str = "data.";

/// Everything that can go wrong while loading or compiling a bundle.
#[derive(Debug, Error)]
pub enum PolicyBundleError {
    #[error("bundle path `{0}` does not exist")]
    BundleNotFound(PathBuf),

    #[error("bundle path `{0}` is not a directory")]
    NotADirectory(PathBuf),

    #[error("bundle at `{0}` has no `{MANIFEST_FILE}`")]
    ManifestMissing(PathBuf),

    #[error("could not read `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("manifest `{path}` is invalid: {source}")]
    ManifestInvalid {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("manifest revision must not be empty")]
    EmptyRevision,

    #[error("manifest must declare at least one root")]
    NoRoots,

    #[error("manifest root `{root}` is invalid: {reason}")]
    InvalidRoot { root: String, reason: &'static str },

    #[error("manifest roots `{outer}` and `{inner}` overlap")]
    OverlappingRoots { outer: String, inner: String },

    #[error("unsupported rego_version {0}; expected 0 or 1")]
    UnsupportedRegoVersion(u64),

    #[error("bundle at `{0}` contains no `.rego` modules")]
    NoModules(PathBuf),

    #[error("module `{path}` is not valid UTF-8")]
    ModuleNotUtf8 { path: PathBuf },

    #[error("`{path}` is {size} bytes, over the per-module limit of {limit}")]
    ModuleTooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },

    #[error("bundle is at least {size} bytes, over the limit of {limit}")]
    BundleTooLarge { size: u64, limit: u64 },

    #[error("bundle nests deeper than the limit of {limit} directories")]
    BundleTooDeep { limit: usize },

    #[error("bundle holds more than {limit} modules")]
    TooManyModules { limit: usize },

    #[error("`{path}` is a symbolic link, which a bundle may not contain")]
    SymlinkNotAllowed { path: PathBuf },

    #[error("module `{path}` failed to compile: {reason}")]
    CompileFailed { path: PathBuf, reason: String },

    #[error("package `{package}` in `{path}` is outside the manifest roots {roots:?}")]
    PackageOutsideRoots {
        package: String,
        path: PathBuf,
        roots: Vec<String>,
    },

    #[error("package `{package}` is declared by both `{first}` and `{second}`")]
    DuplicatePackage {
        package: String,
        first: PathBuf,
        second: PathBuf,
    },

    #[error(
        "`{path}` is a nested data document, which is not supported; move it to the bundle root"
    )]
    NestedDataDocument { path: PathBuf },

    #[error("could not load data document `{path}`: {reason}")]
    DataRejected { path: PathBuf, reason: String },

    #[error("query `{query}` failed: {reason}")]
    QueryFailed { query: String, reason: String },
}

/// Rego language version a bundle is written against.
///
/// Mirrors the `rego_version` manifest field: `0` is the pre-1.0 syntax, `1`
/// requires the `if` and `contains` keywords. Compiling under the wrong
/// version is a hard error rather than a best-effort retry, so a bundle whose
/// meaning changes between versions cannot load by accident.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub enum RegoVersion {
    V0,
    #[default]
    V1,
}

impl TryFrom<u64> for RegoVersion {
    type Error = PolicyBundleError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            other => Err(PolicyBundleError::UnsupportedRegoVersion(other)),
        }
    }
}

impl From<RegoVersion> for u64 {
    fn from(version: RegoVersion) -> Self {
        match version {
            RegoVersion::V0 => 0,
            RegoVersion::V1 => 1,
        }
    }
}

/// The bundle's `.manifest` document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Version identifier for the bundle, typically a commit SHA.
    pub revision: String,
    /// `data` sub-trees this bundle owns. A module may only declare a package
    /// beneath one of these.
    pub roots: Vec<String>,
    #[serde(default)]
    pub rego_version: RegoVersion,
}

impl BundleManifest {
    /// Checks the manifest in isolation, before any module is read.
    pub fn validate(&self) -> Result<(), PolicyBundleError> {
        if self.revision.trim().is_empty() {
            return Err(PolicyBundleError::EmptyRevision);
        }
        if self.roots.is_empty() {
            return Err(PolicyBundleError::NoRoots);
        }

        for root in &self.roots {
            validate_root(root)?;
        }

        // Overlapping roots make ownership ambiguous: a package under the
        // narrower root also sits under the wider one, so the bundle no longer
        // names a single authoritative owner for that sub-tree.
        for (index, outer) in self.roots.iter().enumerate() {
            for inner in &self.roots[index + 1..] {
                if roots_overlap(outer, inner) {
                    return Err(PolicyBundleError::OverlappingRoots {
                        outer: outer.clone(),
                        inner: inner.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// True when `package_path` (without the leading `data.`) is owned by one
    /// of the declared roots.
    fn owns(&self, package_path: &str) -> bool {
        self.roots.iter().any(|root| {
            root.is_empty() || package_path == root || package_path.starts_with(&format!("{root}."))
        })
    }
}

fn validate_root(root: &str) -> Result<(), PolicyBundleError> {
    // The empty root claims the whole `data` document. That is legal, but only
    // on its own: combined with any other root it always overlaps.
    if root.is_empty() {
        return Ok(());
    }

    let reason = if root.starts_with('.') || root.ends_with('.') {
        "must not start or end with `.`"
    } else if root.split('.').any(|segment| segment.is_empty()) {
        "must not contain an empty path segment"
    } else if !root.split('.').all(|segment| {
        segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    }) {
        "path segments may only hold ASCII alphanumerics and `_`"
    } else {
        return Ok(());
    };

    Err(PolicyBundleError::InvalidRoot {
        root: root.to_string(),
        reason,
    })
}

fn roots_overlap(first: &str, second: &str) -> bool {
    if first.is_empty() || second.is_empty() {
        return true;
    }
    first == second
        || first.starts_with(&format!("{second}."))
        || second.starts_with(&format!("{first}."))
}

/// Resource ceilings applied while walking and reading a bundle.
///
/// A bundle is version-controlled input, but the loader still treats it as
/// untrusted: without these bounds a large or deeply nested directory could
/// exhaust memory before a single policy is compiled.
#[derive(Debug, Clone)]
pub struct BundleLimits {
    pub max_modules: usize,
    pub max_module_bytes: u64,
    pub max_total_bytes: u64,
    pub max_depth: usize,
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self {
            max_modules: 256,
            max_module_bytes: 1 << 20,
            max_total_bytes: 16 << 20,
            max_depth: 16,
        }
    }
}

/// Reads and compiles bundles from the filesystem.
#[derive(Debug, Clone, Default)]
pub struct BundleLoader {
    limits: BundleLimits,
}

impl BundleLoader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(limits: BundleLimits) -> Self {
        Self { limits }
    }

    /// Loads the bundle rooted at `dir` and compiles its modules.
    ///
    /// Compilation is all-or-nothing: if any module is unreadable, malformed,
    /// or declares a package outside the manifest roots, the whole load fails
    /// and no partially populated bundle is returned.
    pub fn load(&self, dir: impl AsRef<Path>) -> Result<CompiledBundle, PolicyBundleError> {
        let dir = dir.as_ref();
        self.load_inner(dir).inspect_err(|error| {
            tracing::error!(
                bundle = %dir.display(),
                "policy bundle load failed; guard is running without this bundle: {error}"
            );
        })
    }

    fn load_inner(&self, dir: &Path) -> Result<CompiledBundle, PolicyBundleError> {
        if !dir.exists() {
            return Err(PolicyBundleError::BundleNotFound(dir.to_path_buf()));
        }
        if !dir.is_dir() {
            return Err(PolicyBundleError::NotADirectory(dir.to_path_buf()));
        }

        let manifest = self.read_manifest(dir)?;
        manifest.validate()?;

        let contents = self.walk(dir)?;
        if contents.modules.is_empty() {
            return Err(PolicyBundleError::NoModules(dir.to_path_buf()));
        }

        let mut engine = Engine::new();
        engine.set_rego_v0(manifest.rego_version == RegoVersion::V0);
        engine.set_strict_builtin_errors(true);

        if let Some(data_path) = &contents.data {
            let data = read_text(data_path, self.limits.max_module_bytes)?;
            engine
                .add_data_json(&data)
                .map_err(|error| PolicyBundleError::DataRejected {
                    path: data_path.clone(),
                    reason: first_line(&error.to_string()),
                })?;
        }

        let mut packages: BTreeMap<String, PathBuf> = BTreeMap::new();
        for path in &contents.modules {
            let source = read_text(path, self.limits.max_module_bytes)?;
            let qualified = engine
                .add_policy(path.display().to_string(), source)
                .map_err(|error| PolicyBundleError::CompileFailed {
                    path: path.clone(),
                    reason: first_line(&error.to_string()),
                })?;

            let package = qualified
                .strip_prefix(PACKAGE_PREFIX)
                .unwrap_or(&qualified)
                .to_string();

            if !manifest.owns(&package) {
                return Err(PolicyBundleError::PackageOutsideRoots {
                    package,
                    path: path.clone(),
                    roots: manifest.roots.clone(),
                });
            }

            if let Some(first) = packages.insert(package.clone(), path.clone()) {
                return Err(PolicyBundleError::DuplicatePackage {
                    package,
                    first,
                    second: path.clone(),
                });
            }
        }

        tracing::info!(
            revision = %manifest.revision,
            modules = contents.modules.len(),
            rego_version = u64::from(manifest.rego_version),
            "policy bundle compiled"
        );

        Ok(CompiledBundle {
            revision: manifest.revision,
            roots: manifest.roots,
            rego_version: manifest.rego_version,
            packages: packages.into_keys().collect(),
            engine,
        })
    }

    fn read_manifest(&self, dir: &Path) -> Result<BundleManifest, PolicyBundleError> {
        let path = dir.join(MANIFEST_FILE);
        if !path.is_file() {
            return Err(PolicyBundleError::ManifestMissing(dir.to_path_buf()));
        }
        let raw = read_text(&path, self.limits.max_module_bytes)?;
        serde_json::from_str(&raw)
            .map_err(|source| PolicyBundleError::ManifestInvalid { path, source })
    }

    /// Collects the bundle's `.rego` modules and its optional root data
    /// document, enforcing the configured limits as it descends.
    fn walk(&self, root: &Path) -> Result<BundleContents, PolicyBundleError> {
        let mut contents = BundleContents::default();
        let mut total_bytes = 0u64;
        let mut queue = vec![(root.to_path_buf(), 0usize)];

        while let Some((dir, depth)) = queue.pop() {
            if depth > self.limits.max_depth {
                return Err(PolicyBundleError::BundleTooDeep {
                    limit: self.limits.max_depth,
                });
            }

            let entries = fs::read_dir(&dir).map_err(|source| PolicyBundleError::Io {
                path: dir.clone(),
                source,
            })?;

            for entry in entries {
                let entry = entry.map_err(|source| PolicyBundleError::Io {
                    path: dir.clone(),
                    source,
                })?;
                let path = entry.path();
                let file_type = entry.file_type().map_err(|source| PolicyBundleError::Io {
                    path: path.clone(),
                    source,
                })?;

                // Checked before any read: a symlink is the one entry whose
                // target may sit outside the bundle directory entirely.
                if file_type.is_symlink() {
                    return Err(PolicyBundleError::SymlinkNotAllowed { path });
                }

                if file_type.is_dir() {
                    queue.push((path, depth + 1));
                    continue;
                }

                if path.extension().and_then(|ext| ext.to_str()) == Some(REGO_EXTENSION) {
                    let size = entry
                        .metadata()
                        .map_err(|source| PolicyBundleError::Io {
                            path: path.clone(),
                            source,
                        })?
                        .len();

                    total_bytes = total_bytes.saturating_add(size);
                    if total_bytes > self.limits.max_total_bytes {
                        return Err(PolicyBundleError::BundleTooLarge {
                            size: total_bytes,
                            limit: self.limits.max_total_bytes,
                        });
                    }

                    contents.modules.push(path);
                    if contents.modules.len() > self.limits.max_modules {
                        return Err(PolicyBundleError::TooManyModules {
                            limit: self.limits.max_modules,
                        });
                    }
                } else if path.file_name().and_then(|name| name.to_str()) == Some(DATA_FILE) {
                    // Real OPA scopes each data.json to its own directory.
                    // Rather than half-implement that and quietly drop nested
                    // data, only a root document is accepted and anything
                    // deeper is rejected outright.
                    if dir == root {
                        contents.data = Some(path);
                    } else {
                        return Err(PolicyBundleError::NestedDataDocument { path });
                    }
                }
            }
        }

        // Directory iteration order is filesystem-dependent; sorting keeps a
        // given bundle compiling to the same package list every time.
        contents.modules.sort();
        Ok(contents)
    }
}

#[derive(Debug, Default)]
struct BundleContents {
    modules: Vec<PathBuf>,
    data: Option<PathBuf>,
}

fn read_text(path: &Path, limit: u64) -> Result<String, PolicyBundleError> {
    let size = fs::metadata(path)
        .map_err(|source| PolicyBundleError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();

    if size > limit {
        return Err(PolicyBundleError::ModuleTooLarge {
            path: path.to_path_buf(),
            size,
            limit,
        });
    }

    let bytes = fs::read(path).map_err(|source| PolicyBundleError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    String::from_utf8(bytes).map_err(|_| PolicyBundleError::ModuleNotUtf8 {
        path: path.to_path_buf(),
    })
}

/// Compiler diagnostics can span several lines; the first carries the reason.
fn first_line(message: &str) -> String {
    message.lines().next().unwrap_or(message).trim().to_string()
}

/// A bundle whose modules have been parsed and compiled, ready to evaluate.
#[derive(Debug, Clone)]
pub struct CompiledBundle {
    revision: String,
    roots: Vec<String>,
    rego_version: RegoVersion,
    packages: Vec<String>,
    engine: Engine,
}

impl CompiledBundle {
    /// Version identifier this bundle was published under.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// `data` sub-trees the bundle owns.
    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    /// Rego syntax version the modules were compiled against.
    pub fn rego_version(&self) -> RegoVersion {
        self.rego_version
    }

    /// Compiled packages, sorted, without the leading `data.`.
    pub fn packages(&self) -> &[String] {
        &self.packages
    }

    /// Evaluates `query` against `input` and returns the raw result.
    ///
    /// The caller decides what a result means. This returns an observation; it
    /// never blocks, halts, or otherwise acts on the policy decision.
    ///
    /// Takes `&self`: the engine is cloned per evaluation, so one compiled
    /// bundle can serve many queries without one query's input leaking into
    /// another's.
    pub fn evaluate(
        &self,
        query: &str,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PolicyBundleError> {
        let mut engine = self.engine.clone();

        let input = regorus::Value::from_json_str(&input.to_string()).map_err(|error| {
            PolicyBundleError::QueryFailed {
                query: query.to_string(),
                reason: first_line(&error.to_string()),
            }
        })?;
        engine.set_input(input);

        let results = engine
            .eval_query(query.to_string(), false)
            .map_err(|error| {
                let reason = first_line(&error.to_string());
                tracing::error!(query, revision = %self.revision, "policy query failed: {reason}");
                PolicyBundleError::QueryFailed {
                    query: query.to_string(),
                    reason,
                }
            })?;

        serde_json::to_value(&results).map_err(|error| PolicyBundleError::QueryFailed {
            query: query.to_string(),
            reason: error.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A bundle directory in the system temp dir, removed when the test ends.
    struct TempBundle {
        path: PathBuf,
    }

    impl TempBundle {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = format!(
                "vero-bundle-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::SeqCst)
            );
            let path = std::env::temp_dir().join(unique);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn write(&self, name: &str, contents: &str) -> &Self {
            let path = self.path.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
            self
        }

        fn manifest(&self, revision: &str, roots: &[&str], rego_version: u64) -> &Self {
            self.write(
                MANIFEST_FILE,
                &json!({
                    "revision": revision,
                    "roots": roots,
                    "rego_version": rego_version,
                })
                .to_string(),
            )
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempBundle {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    const ALLOW_POLICY: &str = r#"
package pr.compliance

default allow := false

allow if {
    input.approvals >= 2
}
"#;

    fn manifest_with_roots(roots: &[&str]) -> BundleManifest {
        BundleManifest {
            revision: "rev-1".to_string(),
            roots: roots.iter().map(|root| root.to_string()).collect(),
            rego_version: RegoVersion::V1,
        }
    }

    fn valid_bundle() -> TempBundle {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write("compliance.rego", ALLOW_POLICY);
        bundle
    }

    #[test]
    fn loads_and_compiles_a_well_formed_bundle() {
        let bundle = valid_bundle();
        let compiled = BundleLoader::new().load(bundle.path()).unwrap();

        assert_eq!(compiled.revision(), "rev-1");
        assert_eq!(compiled.roots(), ["pr"]);
        assert_eq!(compiled.packages(), ["pr.compliance"]);
        assert_eq!(compiled.rego_version(), RegoVersion::V1);
    }

    #[test]
    fn compiled_bundle_is_evaluable_against_input() {
        let compiled = BundleLoader::new().load(valid_bundle().path()).unwrap();

        let allowed = compiled
            .evaluate("data.pr.compliance.allow", &json!({ "approvals": 3 }))
            .unwrap();
        assert_eq!(allowed["result"][0]["expressions"][0]["value"], json!(true));

        let denied = compiled
            .evaluate("data.pr.compliance.allow", &json!({ "approvals": 1 }))
            .unwrap();
        assert_eq!(denied["result"][0]["expressions"][0]["value"], json!(false));
    }

    #[test]
    fn evaluation_does_not_leak_input_between_calls() {
        let compiled = BundleLoader::new().load(valid_bundle().path()).unwrap();

        compiled
            .evaluate("data.pr.compliance.allow", &json!({ "approvals": 5 }))
            .unwrap();
        let second = compiled
            .evaluate("data.pr.compliance.allow", &json!({ "approvals": 0 }))
            .unwrap();

        assert_eq!(second["result"][0]["expressions"][0]["value"], json!(false));
    }

    #[test]
    fn rejects_a_malformed_query() {
        let compiled = BundleLoader::new().load(valid_bundle().path()).unwrap();

        assert!(matches!(
            compiled.evaluate("data.pr.compliance.allow[", &json!({})),
            Err(PolicyBundleError::QueryFailed { .. })
        ));
    }

    #[test]
    fn nested_modules_are_discovered_and_ordered_deterministically() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr", "lib"], 1);
        bundle.write("nested/deep/rbac.rego", "package pr.rbac\n");
        bundle.write("shared.rego", "package lib\n");
        bundle.write("nested/crypto.rego", "package pr.crypto\n");

        let compiled = BundleLoader::new().load(bundle.path()).unwrap();
        assert_eq!(compiled.packages(), ["lib", "pr.crypto", "pr.rbac"]);
    }

    #[test]
    fn loads_an_optional_root_data_document() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write(
            DATA_FILE,
            &json!({ "thresholds": { "approvals": 2 } }).to_string(),
        );
        bundle.write(
            "policy.rego",
            "package pr.compliance\n\nallow if { input.approvals >= data.thresholds.approvals }\n",
        );

        let compiled = BundleLoader::new().load(bundle.path()).unwrap();
        let result = compiled
            .evaluate("data.pr.compliance.allow", &json!({ "approvals": 2 }))
            .unwrap();
        assert_eq!(result["result"][0]["expressions"][0]["value"], json!(true));
    }

    #[test]
    fn compiles_rego_v0_syntax_when_the_manifest_asks_for_it() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 0);
        bundle.write(
            "policy.rego",
            "package pr.compliance\n\nallow { input.approvals >= 2 }\n",
        );

        let compiled = BundleLoader::new().load(bundle.path()).unwrap();
        assert_eq!(compiled.rego_version(), RegoVersion::V0);
        assert_eq!(compiled.packages(), ["pr.compliance"]);
    }

    #[test]
    fn rejects_v0_syntax_when_the_manifest_declares_v1() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write(
            "policy.rego",
            "package pr.compliance\n\nallow { input.approvals >= 2 }\n",
        );

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::CompileFailed { .. })
        ));
    }

    #[test]
    fn rejects_an_unsupported_rego_version() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 2);
        bundle.write("policy.rego", ALLOW_POLICY);

        let error = BundleLoader::new().load(bundle.path()).unwrap_err();
        assert!(
            matches!(error, PolicyBundleError::ManifestInvalid { .. }),
            "got: {error}"
        );
        assert!(
            error.to_string().contains("unsupported rego_version 2"),
            "got: {error}"
        );
    }

    #[test]
    fn rejects_a_missing_or_non_directory_bundle_path() {
        let loader = BundleLoader::new();
        let bundle = TempBundle::new();
        bundle.write("not-a-bundle", "");

        assert!(matches!(
            loader.load(bundle.path().join("absent")),
            Err(PolicyBundleError::BundleNotFound(_))
        ));
        assert!(matches!(
            loader.load(bundle.path().join("not-a-bundle")),
            Err(PolicyBundleError::NotADirectory(_))
        ));
    }

    #[test]
    fn rejects_a_bundle_without_a_manifest() {
        let bundle = TempBundle::new();
        bundle.write("policy.rego", ALLOW_POLICY);

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::ManifestMissing(_))
        ));
    }

    #[test]
    fn rejects_a_truncated_manifest() {
        let bundle = TempBundle::new();
        bundle.write(MANIFEST_FILE, r#"{"revision": "rev-1", "roots": ["pr""#);
        bundle.write("policy.rego", ALLOW_POLICY);

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::ManifestInvalid { .. })
        ));
    }

    #[test]
    fn rejects_a_manifest_missing_required_fields() {
        let bundle = TempBundle::new();
        bundle.write(MANIFEST_FILE, r#"{"roots": ["pr"]}"#);
        bundle.write("policy.rego", ALLOW_POLICY);

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::ManifestInvalid { .. })
        ));
    }

    #[test]
    fn rejects_an_empty_revision_or_root_set() {
        let mut blank_revision = manifest_with_roots(&["pr"]);
        blank_revision.revision = "   ".to_string();
        assert!(matches!(
            blank_revision.validate(),
            Err(PolicyBundleError::EmptyRevision)
        ));

        assert!(matches!(
            manifest_with_roots(&[]).validate(),
            Err(PolicyBundleError::NoRoots)
        ));
    }

    #[test]
    fn rejects_malformed_root_paths() {
        for root in [".pr", "pr.", "pr..crypto", "pr/crypto", "pr crypto"] {
            assert!(
                matches!(
                    manifest_with_roots(&[root]).validate(),
                    Err(PolicyBundleError::InvalidRoot { .. })
                ),
                "root `{root}` should be rejected"
            );
        }
    }

    #[test]
    fn rejects_overlapping_roots() {
        for roots in [
            vec!["pr", "pr.crypto"],
            vec!["pr", "pr"],
            vec!["", "pr"],
            vec!["lib", "pr", "pr.rbac"],
        ] {
            assert!(
                matches!(
                    manifest_with_roots(&roots).validate(),
                    Err(PolicyBundleError::OverlappingRoots { .. })
                ),
                "roots {roots:?} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_the_empty_root_only_on_its_own() {
        let manifest = manifest_with_roots(&[""]);
        assert!(manifest.validate().is_ok());
        assert!(manifest.owns("anything.at.all"));
    }

    #[test]
    fn rejects_a_bundle_with_no_modules() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::NoModules(_))
        ));
    }

    #[test]
    fn rejects_malformed_rego() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write(
            "broken.rego",
            "package pr.compliance\n\nallow if { input.x ==\n",
        );

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::CompileFailed { .. })
        ));
    }

    #[test]
    fn rejects_a_module_with_no_package_declaration() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write("headless.rego", "allow if { true }\n");

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::CompileFailed { .. })
        ));
    }

    #[test]
    fn rejects_a_module_that_is_not_utf8() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        fs::write(bundle.path().join("binary.rego"), [0xf0, 0x28, 0x8c, 0x28]).unwrap();

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::ModuleNotUtf8 { .. })
        ));
    }

    #[test]
    fn rejects_a_package_outside_the_declared_roots() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write("escape.rego", "package system.authz\n\nallow if { true }\n");

        let error = BundleLoader::new().load(bundle.path()).unwrap_err();
        assert!(
            matches!(&error, PolicyBundleError::PackageOutsideRoots { package, .. } if package == "system.authz"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_a_package_that_only_prefix_matches_a_root() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write(
            "sneaky.rego",
            "package prod.compliance\n\nallow if { true }\n",
        );

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::PackageOutsideRoots { .. })
        ));
    }

    #[test]
    fn rejects_two_modules_declaring_the_same_package() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write(
            "first.rego",
            "package pr.compliance\n\ndefault allow := false\n",
        );
        bundle.write(
            "second.rego",
            "package pr.compliance\n\ndefault deny := false\n",
        );

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::DuplicatePackage { .. })
        ));
    }

    #[test]
    fn rejects_a_nested_data_document() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write("policy.rego", ALLOW_POLICY);
        bundle.write("nested/data.json", r#"{"a": 1}"#);

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::NestedDataDocument { .. })
        ));
    }

    #[test]
    fn rejects_a_malformed_root_data_document() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write("policy.rego", ALLOW_POLICY);
        bundle.write(DATA_FILE, "{not json");

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::DataRejected { .. })
        ));
    }

    #[test]
    fn rejects_a_module_over_the_size_limit() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write(
            "large.rego",
            &format!("package pr.compliance\n{}", "# pad\n".repeat(64)),
        );

        let loader = BundleLoader::with_limits(BundleLimits {
            max_module_bytes: 32,
            ..BundleLimits::default()
        });
        assert!(matches!(
            loader.load(bundle.path()),
            Err(PolicyBundleError::ModuleTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_a_bundle_over_the_module_count_limit() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        for index in 0..4 {
            bundle.write(&format!("p{index}.rego"), &format!("package pr.p{index}\n"));
        }

        let loader = BundleLoader::with_limits(BundleLimits {
            max_modules: 2,
            ..BundleLimits::default()
        });
        assert!(matches!(
            loader.load(bundle.path()),
            Err(PolicyBundleError::TooManyModules { limit: 2 })
        ));
    }

    #[test]
    fn rejects_a_bundle_over_the_total_size_limit() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write("a.rego", &format!("package pr.a\n{}", "# pad\n".repeat(32)));
        bundle.write("b.rego", &format!("package pr.b\n{}", "# pad\n".repeat(32)));

        let loader = BundleLoader::with_limits(BundleLimits {
            max_total_bytes: 100,
            ..BundleLimits::default()
        });
        assert!(matches!(
            loader.load(bundle.path()),
            Err(PolicyBundleError::BundleTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_a_bundle_nested_past_the_depth_limit() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write("a/b/c/deep.rego", "package pr.deep\n");

        let loader = BundleLoader::with_limits(BundleLimits {
            max_depth: 2,
            ..BundleLimits::default()
        });
        assert!(matches!(
            loader.load(bundle.path()),
            Err(PolicyBundleError::BundleTooDeep { limit: 2 })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_pointing_outside_the_bundle() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write("policy.rego", ALLOW_POLICY);
        std::os::unix::fs::symlink("/etc/passwd", bundle.path().join("leak.rego")).unwrap();

        assert!(matches!(
            BundleLoader::new().load(bundle.path()),
            Err(PolicyBundleError::SymlinkNotAllowed { .. })
        ));
    }

    #[test]
    fn concurrent_loads_of_the_same_bundle_agree() {
        let bundle = valid_bundle();
        let path = bundle.path().to_path_buf();

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let compiled = BundleLoader::new().load(&path).unwrap();
                    (
                        compiled.revision().to_string(),
                        compiled.packages().to_vec(),
                    )
                })
            })
            .collect();

        for handle in handles {
            let (revision, packages) = handle.join().unwrap();
            assert_eq!(revision, "rev-1");
            assert_eq!(packages, ["pr.compliance"]);
        }
    }

    #[test]
    fn a_failed_load_yields_no_bundle_rather_than_a_partial_one() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write("good.rego", ALLOW_POLICY);
        bundle.write("bad.rego", "package pr.broken\n\nallow if { \n");

        // The valid module must not survive on its own: a bundle that loaded
        // "most of" its policy would under-report violations.
        assert!(BundleLoader::new().load(bundle.path()).is_err());
    }

    #[test]
    fn error_messages_name_the_offending_path() {
        let bundle = TempBundle::new();
        bundle.manifest("rev-1", &["pr"], 1);
        bundle.write("broken.rego", "package pr.compliance\n\nallow if { \n");

        let error = BundleLoader::new().load(bundle.path()).unwrap_err();
        assert!(error.to_string().contains("broken.rego"), "got: {error}");
    }

    /// Guards the bundle this repository actually ships: a policy file that
    /// stops compiling should fail here rather than at guard startup.
    #[test]
    fn loads_the_policies_bundle_shipped_with_this_crate() {
        let policies = Path::new(env!("CARGO_MANIFEST_DIR")).join("policies");
        let compiled = BundleLoader::new().load(&policies).unwrap();

        assert_eq!(compiled.rego_version(), RegoVersion::V0);
        assert_eq!(
            compiled.packages(),
            [
                "lib",
                "logic.errors",
                "pr.compliance",
                "pr.crypto",
                "pr.dependencies",
                "rbac.compliance",
            ]
        );
    }

    #[test]
    fn rego_version_round_trips_through_the_manifest() {
        let manifest: BundleManifest =
            serde_json::from_str(r#"{"revision":"r","roots":["pr"],"rego_version":0}"#).unwrap();
        assert_eq!(manifest.rego_version, RegoVersion::V0);

        let encoded = serde_json::to_value(&manifest).unwrap();
        assert_eq!(encoded["rego_version"], json!(0));
    }

    #[test]
    fn rego_version_defaults_to_v1_when_absent() {
        let manifest: BundleManifest =
            serde_json::from_str(r#"{"revision":"r","roots":["pr"]}"#).unwrap();
        assert_eq!(manifest.rego_version, RegoVersion::V1);
    }
}
