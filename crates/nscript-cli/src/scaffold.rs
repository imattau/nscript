//! `nscript new`: write a checked, runnable starter project.
//!
//! Templates live under the repository's `templates/` directory and are
//! embedded in the binary, so `nscript new` works from an installed `nscript`
//! with no checkout. The test in `tests/cli.rs` scaffolds every template and
//! runs the generated `test.sh`, so a template cannot drift from the compiler
//! without CI failing.

use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

struct Template {
    name: &'static str,
    description: &'static str,
    bot: &'static str,
    readme: &'static str,
    /// `(file name inside events/, contents)`.
    events: &'static [(&'static str, &'static str)],
}

const TEST_SCRIPT: &str = include_str!("../../../templates/test.sh");

const TEMPLATES: &[Template] = &[
    Template {
        name: "moderation-bot",
        description: "Kick members who post blocked words (simulation only today)",
        bot: include_str!("../../../templates/moderation-bot/bot.ns"),
        readme: include_str!("../../../templates/moderation-bot/README.md"),
        events: &[
            (
                "spam.json",
                include_str!("../../../templates/moderation-bot/events/spam.json"),
            ),
            (
                "spam.expect",
                include_str!("../../../templates/moderation-bot/events/spam.expect"),
            ),
            (
                "clean.json",
                include_str!("../../../templates/moderation-bot/events/clean.json"),
            ),
            (
                "clean.expect",
                include_str!("../../../templates/moderation-bot/events/clean.expect"),
            ),
        ],
    },
    Template {
        name: "scheduled-poster",
        description: "Publish a note on a timer, signed by a NIP-46 signer",
        bot: include_str!("../../../templates/scheduled-poster/bot.ns"),
        readme: include_str!("../../../templates/scheduled-poster/README.md"),
        events: &[(
            "startup.expect",
            include_str!("../../../templates/scheduled-poster/events/startup.expect"),
        )],
    },
    Template {
        name: "relay-monitor",
        description: "Report NCC-10 operational state for services you depend on (read-only)",
        bot: include_str!("../../../templates/relay-monitor/bot.ns"),
        readme: include_str!("../../../templates/relay-monitor/README.md"),
        events: &[
            (
                "operational.json",
                include_str!("../../../templates/relay-monitor/events/operational.json"),
            ),
            (
                "operational.expect",
                include_str!("../../../templates/relay-monitor/events/operational.expect"),
            ),
            (
                "degraded.json",
                include_str!("../../../templates/relay-monitor/events/degraded.json"),
            ),
            (
                "degraded.expect",
                include_str!("../../../templates/relay-monitor/events/degraded.expect"),
            ),
            (
                "operator-claim.json",
                include_str!("../../../templates/relay-monitor/events/operator-claim.json"),
            ),
            (
                "operator-claim.expect",
                include_str!("../../../templates/relay-monitor/events/operator-claim.expect"),
            ),
        ],
    },
];

pub fn new_project(arguments: &[String]) -> ExitCode {
    match arguments {
        [flag] if flag == "--list" => {
            for template in TEMPLATES {
                println!("{:<18} {}", template.name, template.description);
            }
            ExitCode::SUCCESS
        }
        [name, directory] => {
            let Some(template) = TEMPLATES.iter().find(|template| template.name == name) else {
                eprintln!(
                    "unknown template `{name}`; available: {}",
                    TEMPLATES
                        .iter()
                        .map(|template| template.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                return ExitCode::from(2);
            };
            match write_project(template, Path::new(directory)) {
                Ok(()) => {
                    println!("created {directory} from the {name} template");
                    println!("next:\n  cd {directory}\n  ./test.sh\n  nscript inspect bot.ns");
                    ExitCode::SUCCESS
                }
                Err(message) => {
                    eprintln!("{message}");
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("usage:\n  nscript new --list\n  nscript new <template> <directory>");
            ExitCode::from(2)
        }
    }
}

fn write_project(template: &Template, directory: &Path) -> Result<(), String> {
    if directory.exists()
        && fs::read_dir(directory)
            .map_err(|error| format!("could not read {}: {error}", directory.display()))?
            .next()
            .is_some()
    {
        return Err(format!(
            "{} already exists and is not empty; choose a new directory",
            directory.display()
        ));
    }
    let write = |relative: &str, contents: &str| -> Result<PathBuf, String> {
        let path = directory.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
        fs::write(&path, contents)
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        Ok(path)
    };

    let bot = write("bot.ns", template.bot)?;
    write("README.md", template.readme)?;
    for (file, contents) in template.events {
        write(&format!("events/{file}"), contents)?;
    }
    let script = write("test.sh", TEST_SCRIPT)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("could not make test.sh executable: {error}"))?;
    }
    #[cfg(not(unix))]
    let _ = script;

    // The lockfile records its source path, and test.sh verifies it from
    // inside the project, so it is written relative to the project.
    let (_, mut lockfile) = crate::resolve_lockfile(&[bot.to_string_lossy().into_owned()])
        .map_err(|()| "the template did not resolve; this is a bug in nscript".to_owned())?;
    lockfile["source"] = serde_json::Value::String("bot.ns".to_owned());
    let rendered = serde_json::to_string_pretty(&lockfile).expect("lockfile is serializable");
    write("nscript.lock.json", &format!("{rendered}\n"))?;
    Ok(())
}
