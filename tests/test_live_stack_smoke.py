from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from trusted_runtime.shared.enums import AdapterProvenance, RuntimeDisposition
from trusted_runtime.shared.models import ReceiptRef
from trusted_runtime.smoke import LiveStackRequirementError, run_live_stack_smoke


def test_live_stack_smoke_writes_machine_readable_artifact(tmp_path: Path):
    case_path = Path(__file__).resolve().parents[1] / "examples" / "ai_agent_shell_access.json"
    artifact = run_live_stack_smoke(case_path, tmp_path)
    assert "smoke_test" in artifact
    assert (tmp_path / "live_stack_smoke.json").exists()
    assert (tmp_path / "smoke_decision_output.json").exists()
    assert (tmp_path / "smoke_decision_report.md").exists()

    payload = json.loads((tmp_path / "live_stack_smoke.json").read_text(encoding="utf-8"))
    report_md = (tmp_path / "smoke_decision_report.md").read_text(encoding="utf-8")
    assert payload["smoke_test"]["runtime_disposition"] != "PROCEED"
    assert payload["smoke_test"]["runtime_disposition"] == "HALT"
    assert payload["smoke_test"]["risk_state"] in {"RED", "AMBER"}
    assert payload["smoke_test"]["independently_corroborated"] is False
    assert payload["smoke_test"]["certification_grade_corroboration"] is False
    assert "integration_mode" in payload["smoke_test"]
    assert "integration_mode_report" in payload["smoke_test"]
    assert payload["smoke_test"]["integration_mode_report"] is not None
    assert "components" in payload["smoke_test"]["integration_mode_report"]
    assert "adapter_provenance" in payload["smoke_test"]
    assert "verifier_provenance_summary" in payload["smoke_test"]
    assert "status_line" in payload["smoke_test"]["verifier_provenance_summary"]
    assert "decision_effect" in payload["smoke_test"]["verifier_provenance_summary"]
    assert "verifier provenance status" in report_md
    assert payload["smoke_test"]["verifier_provenance_summary"]["status_line"] in report_md
    assert payload["smoke_test"]["truthfulness_gate_passed"] is True
    assert payload["smoke_test"]["phase4_truthfulness_failures"] == []
    assert payload["smoke_test"]["fail_closed_reason"] is None


def test_live_stack_smoke_require_all_real_fails_closed_when_not_all_real(tmp_path: Path):
    case_path = Path(__file__).resolve().parents[1] / "examples" / "ai_agent_shell_access.json"
    with patch("trusted_runtime.smoke.adapter_status", return_value={"integration_mode": "partial", "adapters": {}}):
        with pytest.raises(LiveStackRequirementError):
            run_live_stack_smoke(case_path, tmp_path, require_all_real=True)


def test_live_stack_smoke_all_real_precheck_does_not_imply_independent_corroboration(tmp_path: Path):
    case_path = Path(__file__).resolve().parents[1] / "examples" / "ai_agent_shell_access.json"
    with patch("trusted_runtime.smoke.adapter_status", return_value={"integration_mode": "all-real", "adapters": {}}):
        artifact = run_live_stack_smoke(case_path, tmp_path, require_all_real=True)

    smoke = artifact["smoke_test"]
    assert smoke["truthfulness_gate_passed"] is True
    assert smoke["independently_corroborated"] is False
    assert smoke["certification_grade_corroboration"] is False
    assert smoke["integration_mode"] in {"all-real", "partial"}


def test_live_stack_smoke_fails_closed_on_phase4_truthfulness_regression(tmp_path: Path):
    case_path = Path(__file__).resolve().parents[1] / "examples" / "ai_agent_shell_access.json"

    class _FakeSophronValidation:
        validation_status = "VALIDATED"
        signal_tiers = {}
        closure_summary = ""
        receipt_linkage = False
        tas_closure_referenced = False
        degradation_reason = None
        l4_closure = {}

    class _FakeDecision:
        integration_mode_report = None
        warrant = None
        normative_summary = type("Norm", (), {"value": "UNDETERMINED"})()
        contested = False
        council = type("Council", (), {"hazards": [], "suspension_triggers": [], "receipt": ReceiptRef(sha256="council")})()
        reconciliation = None
        unresolved_questions = []
        process_provenance = {"council": {"record_sha256": "a"}, "warrant": {"record_sha256": "b"}, "cer_bundle": {"record_sha256": "c"}, "attest_bridge": {"record_sha256": "d"}}
        cer_bundle = type("Cer", (), {"sophron_validation": _FakeSophronValidation(), "receipt": ReceiptRef(sha256="cer")})()
        adapter_provenance = {"council": AdapterProvenance.STUB, "warrant": AdapterProvenance.STUB, "tas": AdapterProvenance.PARTIAL, "cer_bundle": AdapterProvenance.REAL}
        vita_state = {"attest_bridge": {"enabled": False, "verification": {}, "resolver_inputs": {}}, "tas_closure": {"enforcement_maturity": "partial", "closure_bar": {"closure_complete": False, "closure_bar_version": "phase2-v3", "closure_missing": ["task_route"], "enforcement_trace": {"source": "test", "checkpoints": []}}}}
        runtime_disposition = RuntimeDisposition.PROCEED
        independently_corroborated = False
        self_attested_evidence_only = True
        correlation_report = {"certification_grade_corroboration": False, "weakest_detector_independence": "unknown"}
        decision_integrity = type("Integrity", (), {"value": "PARTIAL"})()
        risk_state = type("Risk", (), {"value": "RED"})()
        overall_receipt = ReceiptRef(sha256="overall")
        action_id = "fake"

        def model_dump_json(self, indent=2):
            return "{}"

    with patch("trusted_runtime.smoke.assemble_execution_decision", return_value=_FakeDecision()):
        with pytest.raises(LiveStackRequirementError, match="phase4 truthfulness regression"):
            run_live_stack_smoke(case_path, tmp_path)
