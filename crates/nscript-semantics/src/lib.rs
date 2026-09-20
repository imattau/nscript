//! Static policy checks for `NScript` programs.

use nscript_syntax::{Diagnostic, Program, RuntimeProfile};

const HARDENED_FORBIDDEN: &[&str] = &[
    "SecretKey",
    "Nsec",
    "secret_key",
    "filesystem",
    "process",
    "shell",
    "raw_socket",
    "native_plugin",
];

#[must_use]
pub fn analyze(program: &Program) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    if program.profile == RuntimeProfile::HardenedAgent {
        for (name, span) in &program.identifiers {
            if HARDENED_FORBIDDEN.contains(&name.as_str()) {
                diagnostics.push(Diagnostic {
                    code: "E5001",
                    message: format!("`{name}` is forbidden by the hardened-agent runtime profile"),
                    span: *span,
                });
            }
        }
    }

    if let Some((name, span)) = &program.defaults.signer
        && !program.signers.contains(name)
    {
        diagnostics.push(Diagnostic {
            code: "E1101",
            message: format!("default signer `{name}` is not declared"),
            span: *span,
        });
    }
    if let Some((name, span)) = &program.defaults.relays
        && !program.relaysets.contains(name)
    {
        diagnostics.push(Diagnostic {
            code: "E1101",
            message: format!("default relay set `{name}` is not declared"),
            span: *span,
        });
    }

    for publish in &program.publishes {
        if publish.requires_signer && !publish.explicit_signer && program.defaults.signer.is_none()
        {
            diagnostics.push(Diagnostic {
                code: "E2203",
                message: "unsigned publication has no declared default signer".to_owned(),
                span: publish.span,
            });
        }
        if !publish.explicit_relays && program.defaults.relays.is_none() {
            diagnostics.push(Diagnostic {
                code: "E2204",
                message: "publication has no declared default relay set".to_owned(),
                span: publish.span,
            });
        }
    }

    diagnostics.sort_by_key(|diagnostic| (diagnostic.span.start, diagnostic.code));
    diagnostics
}

#[cfg(test)]
mod tests {
    use nscript_syntax::parse_program;

    use super::analyze;

    fn codes(source: &str) -> Vec<&'static str> {
        let (program, mut diagnostics) = parse_program(source);
        diagnostics.extend(analyze(&program));
        diagnostics
            .into_iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    #[test]
    fn accepts_declared_defaults() {
        let source = "signer account = nip46()\nrelayset public = configured\n\
            defaults { signer: account; relays: public }\npublish Note { content: \"hi\" }\n";
        assert!(codes(source).is_empty());
    }

    #[test]
    fn reports_missing_defaults() {
        assert_eq!(
            codes("publish Note { content: \"hi\" }\n"),
            ["E2203", "E2204"]
        );
    }

    #[test]
    fn hardened_profile_rejects_secret_key() {
        let diagnostics = codes("runtime hardened-agent\nlet key: SecretKey = keys.generate()\n");
        assert_eq!(diagnostics, ["E5001"]);
    }

    #[test]
    fn accepts_default_publish_fixture() {
        let source = include_str!("../../../conformance/valid/default-publish.ns");
        assert!(codes(source).is_empty());
    }

    #[test]
    fn rejects_missing_default_fixtures() {
        let signer = include_str!("../../../conformance/invalid/missing-default-signer.ns");
        let relays = include_str!("../../../conformance/invalid/missing-default-relays.ns");
        assert_eq!(codes(signer), ["E2203"]);
        assert_eq!(codes(relays), ["E2204"]);
    }
}
