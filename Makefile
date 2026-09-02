# Porting Kit — smoke-test every harness so the kit itself never rots.
# `make check-kit` runs each harness's self-test; the core needs only python3 +
# bash (no Rust toolchain), so it runs anywhere and gates changes to the kit.
# The skeleton gate additionally builds/lints the shipped skeleton WHEN a Rust
# toolchain is present (it SKIPs cleanly otherwise) — LESSONS #9.

PY := python3
H  := harnesses

.PHONY: check-kit
check-kit:
	@echo "== unsafe-audit ==";     $(PY) $(H)/unsafe-audit/audit_unsafe.py --self-test
	@echo "== normalize ==";        $(PY) $(H)/differential/normalize.py --self-test
	@echo "== diff_run ==";         $(PY) $(H)/differential/diff_run.py --self-test
	@echo "== golden ==";           $(PY) $(H)/golden/golden.py --self-test
	@echo "== c-flaw-scan ==";      $(PY) $(H)/c-flaw-scan/scan_c_flaws.py --self-test
	@echo "== api-coverage ==";     $(PY) $(H)/api-coverage/check_api.py --self-test
	@echo "== control-coverage =="; $(PY) $(H)/control-coverage/check_controls.py --self-test
	@echo "== control-coverage: the shipped gate TEMPLATE must wire every control =="; \
	  $(PY) $(H)/control-coverage/check_controls.py --controls CLAUDE.md --gate skeleton/check.sh
	@echo "== diff-fuzz ==";        $(PY) $(H)/diff-fuzz/diff_fuzz.py --self-test
	@echo "== probe ==";            $(PY) $(H)/probe/probe.py --self-test
	@echo "== perf-gate ==";        $(PY) $(H)/perf/perf_gate.py --self-test
	@echo "== cando ==";            $(PY) $(H)/cando/cando_diff.py --self-test
	@echo "== library-differential =="; $(PY) $(H)/library-differential/lib_diff.py --self-test
	@echo "== progress ==";         $(PY) $(H)/progress/progress.py --self-test
	@echo "== fuzz scaffolder ==";  bash  $(H)/fuzz/gen_fuzz_target.sh --check
	@echo "== supply-chain ==";     bash  $(H)/supply-chain/run_supply_chain.sh --check
	@echo "== sanitizers ==";       bash  $(H)/sanitizers/run_sanitizers.sh --check
	@echo "== matrix parses ==";    $(PY) -c "import tomllib; tomllib.load(open('$(H)/differential/input-matrix.example.toml','rb')); print('PASS  matrix parses')"
	@echo "== vectors parse ==";    $(PY) -c "import tomllib; tomllib.load(open('$(H)/cando/vectors.example.toml','rb')); print('PASS  vectors parse')"
	@echo "== threat-model self-test =="; $(PY) $(H)/threat-model/check_threat_model.py --self-test
	@echo "== threat-model template =="; $(PY) $(H)/threat-model/check_threat_model.py skeleton/THREAT-MODEL.md --template
	@echo "== doc-flags self-test ==="; $(PY) $(H)/doc-check/check_doc_flags.py --self-test
	@echo "== doc-flags integrity =="; $(PY) $(H)/doc-check/check_doc_flags.py
	@echo "== lessons-pinned self-test =="; $(PY) $(H)/doc-check/check_lessons_pinned.py --self-test
	@echo "== lessons-pinned integrity =="; $(PY) $(H)/doc-check/check_lessons_pinned.py
	@echo "== skills self-test =="; $(PY) skills/check_skills.py --self-test
	@echo "== skills integrity =="; $(PY) skills/check_skills.py
	@echo "== gate-mutation self-test =="; $(PY) $(H)/gate-mutation/mutate_gates.py --self-test
	@echo "== gate-mutation sweep =="; $(PY) $(H)/gate-mutation/mutate_gates.py .
	@echo "== skeleton gate ==";    bash  $(H)/skeleton-check/check_skeleton.sh
	@echo ""
	@echo "check-kit: ALL HARNESSES OK"

.PHONY: help
help:
	@echo "make check-kit   smoke-test every harness (python3 + bash only)"
