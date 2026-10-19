"""Unit tests for the evaluation module."""

import json

from forensight import evaluate, scoring


def test_metrics_confusion_matrix():
    m = evaluate.metrics([80, 40, 5], [50, 0, 0, 0], threshold=30)
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (2, 1, 1, 3)
    assert m["precision"] == round(2 / 3, 4) and m["recall"] == round(2 / 3, 4)
    assert m["fpr"] == 0.25


def test_email_files_skips_index_and_samples(tmp_path):
    for name in ("00001.abc", "00002.def", "00003.ghi", "cmds", ".hidden"):
        (tmp_path / name).write_text("x")
    assert [p.name for p in evaluate.email_files(tmp_path)] == ["00001.abc", "00002.def", "00003.ghi"]
    assert len(evaluate.email_files(tmp_path, limit=2)) == 2


def test_prompt_injection_test_set():
    results = {r["case"]: r for r in evaluate.injection_test()}
    attacks = [r for r in results.values() if r["kind"] == "attack"]
    assert all(r["detected"] for r in attacks)
    assert not any(r["detected"] for r in results.values() if r["kind"] == "evasion")
    assert not results["hidden preheader"]["detected"] and not results["ignore my email"]["detected"]
    assert results["white text"]["hidden_kept_from_model"]


def test_evaluate_writes_results(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    phish, ham = tmp_path / "phish", tmp_path / "ham"
    phish.mkdir(), ham.mkdir()
    for folder, names in ((phish, ["a.eml", "b.eml"]), (ham, ["1", "2", "3"])):
        for name in names:
            (folder / name).write_text("x")
    fake = {"a.eml": 70, "b.eml": 20, "1": 0, "2": 35, "3": 4}

    def score_file(path):
        findings = [{"section": "Headers", "severity": "high", "title": "t", "detail": "", "context": ""}]
        report = scoring.score_findings(findings, path)
        report.score = fake[path.name]
        return report, 0.01

    monkeypatch.setattr(evaluate, "score_file", score_file)
    result = evaluate.evaluate(phish, [ham])
    at30 = next(m for m in result["thresholds"] if m["threshold"] == 30)
    assert (at30["tp"], at30["fn"], at30["fp"], at30["tn"]) == (1, 1, 1, 2)
    saved = json.loads((tmp_path / "output" / "evaluation" / "metrics.json").read_text())
    assert saved["legitimate_emails"] == 3
    assert (tmp_path / "output" / "evaluation" / "scores.csv").exists()
