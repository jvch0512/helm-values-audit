# Validation on real data

Counts below were produced by running the tool on public data, not on the synthetic samples in `examples/`.

## Corpus
prometheus-community/helm-charts at `813b226` and argoproj/argo-helm at `03c4e1e`.

## Result
After the fixes, 52 values files produce 25 findings. The first run produced 232 files and 67 findings because it also read files that are not chart values.

## What the real data exposed (all fixed, with regression tests)
- Only files named like `values*.yaml` are read now. Template sources, `.github` files and unit-test fixtures were being parsed as values.
- Chart-testing fixtures under `ci/` are skipped, because they are test inputs and not deployable defaults.
- Keys such as `selector`, `field`, `persist` and `id-` caused false HLM001 secret findings and are now in the skip list. Values that are references (for example names of existing secrets) are not reported as hard-coded secrets.

## What it finds that is real
Privileged containers, `hostNetwork`, `hostPID` and `allowPrivilegeEscalation: true` in exporter charts that need them by design. These are legitimate to review even when intended.
