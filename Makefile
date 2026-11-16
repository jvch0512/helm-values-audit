.PHONY: test sample

test:
	lua5.4 tests/test.lua && bash tests/cli.sh

sample:
	mkdir -p docs site
	bin/helm-values-audit examples > docs/sample-output.txt; true
	bin/helm-values-audit examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "helm-values-audit" "Audits Helm values.yaml files for hard-coded secrets, weak default passwords, privileged containers, root users, latest tags and disabled TLS verification. Lua." "Synthetic data."
