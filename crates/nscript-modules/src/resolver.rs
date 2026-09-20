use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Path, PathBuf},
};

use semver::{Version, VersionReq};

use crate::{ModuleDependency, ModuleDescriptor, parse_module};

const BUILTINS: &[(&str, &str)] = &[
    ("keys", include_str!("../../../modules/std/keys/0.1.0.nsm")),
    (
        "nip02",
        include_str!("../../../modules/std/nip02/0.1.0.nsm"),
    ),
    (
        "nip5a",
        include_str!("../../../modules/std/nip5a/0.1.0.nsm"),
    ),
    (
        "nip09",
        include_str!("../../../modules/std/nip09/0.1.0.nsm"),
    ),
    (
        "nip25",
        include_str!("../../../modules/std/nip25/0.1.0.nsm"),
    ),
    (
        "nip51",
        include_str!("../../../modules/std/nip51/0.1.0.nsm"),
    ),
    (
        "nip52",
        include_str!("../../../modules/std/nip52/0.1.0.nsm"),
    ),
    (
        "nip57",
        include_str!("../../../modules/std/nip57/0.1.0.nsm"),
    ),
    (
        "nip01",
        include_str!("../../../modules/std/nip01/0.1.0.nsm"),
    ),
    (
        "nip10",
        include_str!("../../../modules/std/nip10/0.1.0.nsm"),
    ),
    (
        "nip18",
        include_str!("../../../modules/std/nip18/0.1.0.nsm"),
    ),
    (
        "nip22",
        include_str!("../../../modules/std/nip22/0.1.0.nsm"),
    ),
    (
        "nip23",
        include_str!("../../../modules/std/nip23/0.1.0.nsm"),
    ),
    (
        "nip29",
        include_str!("../../../modules/std/nip29/0.1.0.nsm"),
    ),
    (
        "nip32",
        include_str!("../../../modules/std/nip32/0.1.0.nsm"),
    ),
    (
        "nip37",
        include_str!("../../../modules/std/nip37/0.1.0.nsm"),
    ),
    (
        "nip38",
        include_str!("../../../modules/std/nip38/0.1.0.nsm"),
    ),
    (
        "nip19",
        include_str!("../../../modules/std/nip19/0.1.0.nsm"),
    ),
    (
        "nip46",
        include_str!("../../../modules/std/nip46/0.1.0.nsm"),
    ),
    (
        "nip44",
        include_str!("../../../modules/std/nip44/0.1.0.nsm"),
    ),
    (
        "nip59",
        include_str!("../../../modules/std/nip59/0.1.0.nsm"),
    ),
    (
        "nip17",
        include_str!("../../../modules/std/nip17/0.1.0.nsm"),
    ),
    (
        "nip65",
        include_str!("../../../modules/std/nip65/0.1.0.nsm"),
    ),
    (
        "nip66",
        include_str!("../../../modules/std/nip66/0.1.0.nsm"),
    ),
    (
        "nip78",
        include_str!("../../../modules/std/nip78/0.1.0.nsm"),
    ),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModuleOrigin {
    BuiltIn(String),
    File(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredModule {
    pub descriptor: ModuleDescriptor,
    pub origin: ModuleOrigin,
}

#[derive(Clone, Debug, Default)]
pub struct ModuleRegistry {
    entries: BTreeMap<String, BTreeMap<Version, RegisteredModule>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedModuleGraph {
    pub modules: BTreeMap<String, RegisteredModule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    Conflict {
        name: String,
        version: Version,
        first: Box<ModuleOrigin>,
        second: Box<ModuleOrigin>,
    },
    Missing {
        name: String,
        requirements: Vec<VersionReq>,
    },
    Cycle(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryError {
    pub path: PathBuf,
    pub message: String,
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.message)
    }
}

impl std::error::Error for DiscoveryError {}

impl fmt::Display for ResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { name, version, .. } => {
                write!(formatter, "conflicting descriptors for `{name}@{version}`")
            }
            Self::Missing { name, requirements } => {
                let requirements = requirements
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(formatter, "no version of `{name}` satisfies {requirements}")
            }
            Self::Cycle(path) => {
                write!(formatter, "module dependency cycle: {}", path.join(" -> "))
            }
        }
    }
}

impl std::error::Error for ResolutionError {}

impl ModuleRegistry {
    /// Creates a registry containing the standard declarative modules.
    ///
    /// # Panics
    ///
    /// Panics when a built-in checked into this compiler is invalid or conflicts
    /// with another built-in. CI validates this invariant.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut registry = Self::default();
        for (name, source) in BUILTINS {
            let (descriptor, diagnostics) = parse_module(source);
            assert!(
                diagnostics.is_empty(),
                "invalid built-in {name}: {diagnostics:#?}"
            );
            registry
                .register(
                    descriptor.expect("a valid built-in has a descriptor"),
                    ModuleOrigin::BuiltIn((*name).to_owned()),
                )
                .expect("built-ins have unique identities");
        }
        registry
    }

    /// Discovers and registers `.nsm` files under one deterministic module root.
    ///
    /// # Errors
    ///
    /// Returns an error for inaccessible roots, paths escaping through symlinks,
    /// invalid schemas or layouts, and conflicting module identities.
    pub fn load_root(&mut self, root: &Path) -> Result<usize, DiscoveryError> {
        let canonical_root = root.canonicalize().map_err(|error| DiscoveryError {
            path: root.to_path_buf(),
            message: error.to_string(),
        })?;
        let mut files = Vec::new();
        collect_module_files(&canonical_root, &canonical_root, &mut files)?;
        files.sort();
        let mut loaded = 0;
        for path in files {
            let source = fs::read_to_string(&path).map_err(|error| DiscoveryError {
                path: path.clone(),
                message: error.to_string(),
            })?;
            let (descriptor, diagnostics) = parse_module(&source);
            let Some(descriptor) = descriptor else {
                let message = diagnostics
                    .first()
                    .map_or_else(|| "invalid module".to_owned(), |item| item.message.clone());
                return Err(DiscoveryError { path, message });
            };
            validate_layout(&canonical_root, &path, &descriptor)?;
            self.register(descriptor, ModuleOrigin::File(path.clone()))
                .map_err(|error| DiscoveryError {
                    path,
                    message: error.to_string(),
                })?;
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Registers one validated descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ResolutionError::Conflict`] when the registry already contains
    /// the same module name and version with a different canonical hash.
    pub fn register(
        &mut self,
        descriptor: ModuleDescriptor,
        origin: ModuleOrigin,
    ) -> Result<(), ResolutionError> {
        let name = descriptor.id.name.clone();
        let version = descriptor.id.version.clone();
        let versions = self.entries.entry(name.clone()).or_default();
        if let Some(existing) = versions.get(&version) {
            if existing.descriptor.canonical_hash == descriptor.canonical_hash {
                return Ok(());
            }
            return Err(ResolutionError::Conflict {
                name,
                version,
                first: Box::new(existing.origin.clone()),
                second: Box::new(origin),
            });
        }
        versions.insert(version, RegisteredModule { descriptor, origin });
        Ok(())
    }

    /// Resolves roots and their transitive dependencies to one deterministic
    /// version per module name.
    ///
    /// # Errors
    ///
    /// Returns [`ResolutionError::Missing`] when no compatible version exists,
    /// or [`ResolutionError::Cycle`] when the selected graph contains a cycle.
    pub fn resolve(
        &self,
        roots: &[ModuleDependency],
    ) -> Result<ResolvedModuleGraph, ResolutionError> {
        let mut constraints = BTreeMap::<String, Vec<VersionReq>>::new();
        for root in roots {
            constraints
                .entry(root.name.clone())
                .or_default()
                .push(root.requirement.clone());
        }
        let selected = self.solve(&constraints, &BTreeMap::new())?;
        if let Some(cycle) = dependency_cycle(&selected) {
            return Err(ResolutionError::Cycle(cycle));
        }
        Ok(ResolvedModuleGraph { modules: selected })
    }

    fn solve(
        &self,
        constraints: &BTreeMap<String, Vec<VersionReq>>,
        selected: &BTreeMap<String, RegisteredModule>,
    ) -> Result<BTreeMap<String, RegisteredModule>, ResolutionError> {
        for (name, module) in selected {
            if let Some(requirements) = constraints.get(name)
                && !requirements
                    .iter()
                    .all(|item| item.matches(&module.descriptor.id.version))
            {
                return Err(ResolutionError::Missing {
                    name: name.clone(),
                    requirements: requirements.clone(),
                });
            }
        }

        let next = constraints
            .keys()
            .find(|name| !selected.contains_key(*name));
        let Some(name) = next else {
            return Ok(selected.clone());
        };
        let requirements = constraints
            .get(name)
            .expect("the next unresolved name came from constraints");
        let Some(versions) = self.entries.get(name) else {
            return Err(ResolutionError::Missing {
                name: name.clone(),
                requirements: requirements.clone(),
            });
        };
        let mut last_error = None;
        for (_, candidate) in versions.iter().rev().filter(|(version, _)| {
            requirements
                .iter()
                .all(|requirement| requirement.matches(version))
        }) {
            let mut next_selected = selected.clone();
            next_selected.insert(name.clone(), candidate.clone());
            let mut next_constraints = constraints.clone();
            for dependency in &candidate.descriptor.dependencies {
                next_constraints
                    .entry(dependency.name.clone())
                    .or_default()
                    .push(dependency.requirement.clone());
            }
            match self.solve(&next_constraints, &next_selected) {
                Ok(solution) => return Ok(solution),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| ResolutionError::Missing {
            name: name.clone(),
            requirements: requirements.clone(),
        }))
    }
}

fn collect_module_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), DiscoveryError> {
    let entries = fs::read_dir(directory).map_err(|error| DiscoveryError {
        path: directory.to_path_buf(),
        message: error.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| DiscoveryError {
            path: directory.to_path_buf(),
            message: error.to_string(),
        })?;
        let canonical = entry
            .path()
            .canonicalize()
            .map_err(|error| DiscoveryError {
                path: entry.path(),
                message: error.to_string(),
            })?;
        if !canonical.starts_with(root) {
            return Err(DiscoveryError {
                path: entry.path(),
                message: "module path escapes its configured root".to_owned(),
            });
        }
        if canonical.is_dir() {
            collect_module_files(root, &canonical, output)?;
        } else if canonical
            .extension()
            .is_some_and(|extension| extension == "nsm")
        {
            output.push(canonical);
        }
    }
    Ok(())
}

fn validate_layout(
    root: &Path,
    path: &Path,
    descriptor: &ModuleDescriptor,
) -> Result<(), DiscoveryError> {
    let mut expected = root.to_path_buf();
    for segment in descriptor.id.name.split("::") {
        expected.push(segment);
    }
    expected.push(format!("{}.nsm", descriptor.id.version));
    if path == expected {
        Ok(())
    } else {
        Err(DiscoveryError {
            path: path.to_path_buf(),
            message: format!("expected module at {}", expected.display()),
        })
    }
}

fn dependency_cycle(selected: &BTreeMap<String, RegisteredModule>) -> Option<Vec<String>> {
    fn visit(
        name: &str,
        selected: &BTreeMap<String, RegisteredModule>,
        visiting: &mut Vec<String>,
        complete: &mut BTreeSet<String>,
    ) -> Option<Vec<String>> {
        if let Some(position) = visiting.iter().position(|item| item == name) {
            let mut cycle = visiting[position..].to_vec();
            cycle.push(name.to_owned());
            return Some(cycle);
        }
        if complete.contains(name) {
            return None;
        }
        visiting.push(name.to_owned());
        if let Some(module) = selected.get(name) {
            for dependency in &module.descriptor.dependencies {
                if let Some(cycle) = visit(&dependency.name, selected, visiting, complete) {
                    return Some(cycle);
                }
            }
        }
        visiting.pop();
        complete.insert(name.to_owned());
        None
    }

    let mut complete = BTreeSet::new();
    for name in selected.keys() {
        if let Some(cycle) = visit(name, selected, &mut Vec::new(), &mut complete) {
            return Some(cycle);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use semver::{Version, VersionReq};

    use super::{ModuleOrigin, ModuleRegistry, ResolutionError};
    use crate::{CANONICAL_ENCODING_VERSION, ModuleDependency, ModuleDescriptor, ModuleId};

    fn module(name: &str, version: &str, dependencies: &[(&str, &str)]) -> ModuleDescriptor {
        ModuleDescriptor {
            id: ModuleId {
                name: name.to_owned(),
                version: Version::parse(version).unwrap(),
            },
            language: VersionReq::STAR,
            reference: None,
            dependencies: dependencies
                .iter()
                .map(|(name, requirement)| ModuleDependency {
                    name: (*name).to_owned(),
                    requirement: VersionReq::parse(requirement).unwrap(),
                })
                .collect(),
            types: Vec::new(),
            validators: Vec::new(),
            functions: Vec::new(),
            events: Vec::new(),
            tags: Vec::new(),
            operations: Vec::new(),
            errors: Vec::new(),
            vectors: Vec::new(),
            canonical_encoding: CANONICAL_ENCODING_VERSION,
            canonical_hash: ShaForTest::hash(name, version),
        }
    }

    struct ShaForTest;

    impl ShaForTest {
        fn hash(name: &str, version: &str) -> [u8; 32] {
            let mut output = [0; 32];
            for (target, source) in output.iter_mut().zip(name.bytes().chain(version.bytes())) {
                *target = source;
            }
            output
        }
    }

    #[test]
    fn selects_highest_compatible_transitive_versions() {
        let mut registry = ModuleRegistry::default();
        for descriptor in [
            module("app", "1.0.0", &[("base", ">=1, <3")]),
            module("base", "1.0.0", &[]),
            module("base", "2.0.0", &[]),
            module("base", "3.0.0", &[]),
        ] {
            registry
                .register(descriptor, ModuleOrigin::BuiltIn("test".to_owned()))
                .unwrap();
        }
        let graph = registry
            .resolve(&[ModuleDependency {
                name: "app".to_owned(),
                requirement: VersionReq::STAR,
            }])
            .unwrap();
        assert_eq!(
            graph.modules["base"].descriptor.id.version,
            Version::new(2, 0, 0)
        );
    }

    #[test]
    fn rejects_cycles() {
        let mut registry = ModuleRegistry::default();
        registry
            .register(
                module("a", "1.0.0", &[("b", "*")]),
                ModuleOrigin::BuiltIn("test".to_owned()),
            )
            .unwrap();
        registry
            .register(
                module("b", "1.0.0", &[("a", "*")]),
                ModuleOrigin::BuiltIn("test".to_owned()),
            )
            .unwrap();
        let error = registry
            .resolve(&[ModuleDependency {
                name: "a".to_owned(),
                requirement: VersionReq::STAR,
            }])
            .unwrap_err();
        assert!(matches!(error, ResolutionError::Cycle(_)));
    }

    #[test]
    fn builtins_resolve_transitively() {
        let registry = ModuleRegistry::with_builtins();
        let graph = registry
            .resolve(&[ModuleDependency {
                name: "nip10".to_owned(),
                requirement: VersionReq::STAR,
            }])
            .unwrap();
        assert!(graph.modules.contains_key("nip01"));
        assert!(graph.modules.contains_key("nip10"));
    }

    #[test]
    fn discovers_standard_layout() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../modules/std");
        let mut registry = ModuleRegistry::default();
        assert_eq!(registry.load_root(&root).unwrap(), 25);
    }

    #[test]
    fn resolves_private_message_module_graph() {
        let registry = ModuleRegistry::with_builtins();
        let graph = registry
            .resolve(&[ModuleDependency {
                name: "nip17".to_owned(),
                requirement: VersionReq::STAR,
            }])
            .unwrap();
        assert!(graph.modules.contains_key("nip17"));
        assert!(graph.modules.contains_key("nip44"));
        assert!(graph.modules.contains_key("nip59"));
    }
}
