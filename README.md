# helm-values-audit

helm-values-audit reads Helm `values.yaml` files (and any other YAML) with a small built-in YAML reader and reports risky defaults: hard-coded secrets and tokens, weak default passwords, `privileged: true`, host namespaces, privilege escalation, containers that run as root, dangerous Linux capabilities, `latest` or missing image tags, writable root filesystems and disabled TLS verification. Findings carry the file, line and key path.

**Live demo:** https://jvch0512.github.io/helm-values-audit/ (Synthetic data.)

Lua 5.4, standard library only. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
bin/helm-values-audit examples
bin/helm-values-audit ./charts --tsv
bin/helm-values-audit ./charts --fail-on high       # exit 1 on any high finding
```

Exit codes: 0 ok, 1 findings at or above `--fail-on`, 2 bad input. Output is human text by default and TSV with `--tsv` (`# N files, M findings`, then `SEVERITY<TAB>RULE<TAB>WHERE<TAB>MESSAGE`).

| Rule | Severity | What it catches |
|---|---|---|
| HLM001 | high | a secret, password, token or key with a hard-coded literal value |
| HLM002 | high | a password with a weak default such as admin, password or changeme |
| HLM003 | high | `privileged: true`, `hostNetwork`, `hostPID`, `hostIPC` or `allowPrivilegeEscalation: true` |
| HLM004 | medium | `runAsUser: 0` or `runAsNonRoot: false` |
| HLM005 | low | an image with the `latest` tag or no tag |
| HLM006 | low | `readOnlyRootFilesystem: false` |
| HLM007 | medium | TLS verification disabled: `insecureSkipVerify`, `skipTlsVerify`, `sslVerify: false` |
| HLM008 | high | a capability of SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE or ALL added |
| HLM000 | info | the file is empty or is not YAML this reader understands |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- The built-in YAML reader covers block maps and lists, quoted strings, flow lists and maps on one line, comments and `|` or `>` block scalars. Anchors, aliases, tags and multi-line flow collections are not interpreted.
- Values containing `{{` (Helm templates) and empty values are not reported as secrets.
- Keys whose name suggests a reference rather than a value (`existingSecret`, `secretName`, `passwordKey`, `tokenFile` and similar) are skipped.
- Templates in `templates/` are not rendered. Only values files and other plain YAML are read.

## Where it fits

Reviewing Helm charts before deployment, chart supply chain checks and quick looks at customer values files.

## Tests

```bash
make test    # A Lua test script: the YAML reader, every rule on good and bad values, template and reference skipping, hostile input, fuzzing and CLI exit codes
```

MIT.
