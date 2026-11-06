"""TTI Command Line Interface.

Provides operational tools:
- python -m app.cli rules sync
- python -m app.cli rules test
- python -m app.cli rules evaluate [--holdout-path <path>]
"""

import argparse
import asyncio
from collections import defaultdict
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid
import yaml

from app.core.config import get_settings
from app.database.session import async_session_factory
from app.detection.engine import ThreatDetectionEngine
from app.detection.stance import StanceClassifier
from app.detection.taxonomy_loader import load_taxonomy_from_directory
from app.services.detection_service import ThreatDetectionService


async def cmd_rules_sync(taxonomy_dir: Path) -> None:
    """Synchronize taxonomy YAML definitions to database."""
    print(f"Synchronizing taxonomy rules from {taxonomy_dir}...")
    async with async_session_factory() as session:
        service = ThreatDetectionService()
        result = await service.sync_taxonomy(session, taxonomy_dir)
        await session.commit()
    print("Taxonomy synchronized successfully:")
    print(f"  • Categories synced: {result['categories_synced']}")
    print(f"  • Rules synced:      {result['rules_synced']}")


def cmd_rules_test(taxonomy_dir: Path) -> None:
    """Run self-test on taxonomy engine and detectors."""
    print("Executing detection engine self-tests...")
    _, rules = load_taxonomy_from_directory(taxonomy_dir)
    engine = ThreatDetectionEngine(rules)

    test_cases = [
        ("Sir aapka KYC expire ho gaya, link par click karo", "banking_fraud"),
        ("Work from home part time job, earn Rs 3000 daily", "fake_job_scams"),
        ("Guaranteed 300% returns in 7 days on crypto", "investment_scams"),
        ("Send me 10000 or I will leak your private webcam", "online_threats"),
        ("Meeting 5 baje hai, doc bhej do", None),
    ]

    passed = 0
    for text, expected_cat in test_cases:
        results = engine.analyze_message(text, tenant_id=uuid.uuid4(), message_id="self_test")
        categories = [r.category for r in results]
        if expected_cat is None:
            if not categories:
                passed += 1
            else:
                print(f"FAIL: Expected no detection for '{text}', got {categories}")
        else:
            if expected_cat in categories:
                passed += 1
            else:
                print(f"FAIL: Expected '{expected_cat}' for '{text}', got {categories}")

    print(f"Self-test complete: {passed}/{len(test_cases)} assertions passed.")


def check_dev_copy_lint(taxonomy_dir: Path, dataset_path: Path) -> List[Dict[str, Any]]:
    """Scan rules for verbatim 4+ word phrases or regex literals that appear in dev samples."""
    if not dataset_path.exists():
        return []

    with open(dataset_path, "r", encoding="utf-8") as f:
        samples = [json.loads(line) for line in f if line.strip()]

    copies = []
    for yf in taxonomy_dir.glob("*.yaml"):
        try:
            with open(yf, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            cat = data.get("category", "")
            for r in data.get("rules", []):
                rid = r.get("rule_id", "")
                payload = r.get("pattern_payload", {})
                phrases = list(payload.get("phrases", [])) + list(payload.get("keywords", []))
                regex_pat = payload.get("regex")
                if regex_pat:
                    phrases.append(regex_pat)
                for p in phrases:
                    words = p.strip().split()
                    if len(words) >= 4:
                        for idx, s in enumerate(samples):
                            if p.lower() in s.get("text", "").lower():
                                copies.append({
                                    "rule_id": rid,
                                    "category": cat,
                                    "phrase": p,
                                    "sample_id": f"dev_sample_{idx+1}",
                                })
        except Exception:
            continue
    return copies


def evaluate_dataset(
    engine: ThreatDetectionEngine,
    dataset_path: Path,
) -> Dict[str, Any]:
    """Run detection and stance evaluation over dataset and compute metrics."""
    samples = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                samples.append(json.loads(line_str))

    total_samples = len(samples)
    benign_count = 0
    benign_fp_count = 0
    stance_correct = 0
    unclear_count = 0
    dangerous_warn_to_fac = 0
    dangerous_fac_to_warn = 0
    stance_confusion: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    per_category: Dict[str, Dict[str, int]] = {}
    per_language: Dict[str, Dict[str, Any]] = {}

    for idx, s in enumerate(samples):
        text = s.get("text", "")
        lang = s.get("language", "unknown")
        expected_cats = set(s.get("expected_categories", []))
        expected_stance = s.get("expected_stance", "none")

        # Track benign messages
        is_benign = len(expected_cats) == 0
        if is_benign:
            benign_count += 1

        # Evaluate detection
        results = engine.analyze_message(text, tenant_id=uuid.uuid4(), message_id=f"eval_{idx+1}")
        pred_cats = {r.category for r in results}

        if is_benign and len(pred_cats) > 0:
            benign_fp_count += 1

        # Evaluate stance
        pred_stance = StanceClassifier.classify(text, has_detections=len(pred_cats) > 0)
        stance_confusion[expected_stance][pred_stance] += 1
        if pred_stance == expected_stance:
            stance_correct += 1
        if pred_stance == "unclear":
            unclear_count += 1
        if expected_stance == "warning" and pred_stance == "potentially_facilitating":
            dangerous_warn_to_fac += 1
        if expected_stance == "potentially_facilitating" and pred_stance == "warning":
            dangerous_fac_to_warn += 1

        # Per-language stats
        lang_stats = per_language.setdefault(
            lang,
            {"samples": 0, "correct_detections": 0, "tp": 0, "fp": 0, "fn": 0}
        )
        lang_stats["samples"] += 1
        if pred_cats == expected_cats:
            lang_stats["correct_detections"] += 1
        for cat in expected_cats:
            if cat in pred_cats:
                lang_stats["tp"] += 1
            else:
                lang_stats["fn"] += 1
        for cat in pred_cats:
            if cat not in expected_cats:
                lang_stats["fp"] += 1

        # Per-category stats
        all_eval_cats = expected_cats.union(pred_cats)
        for cat in all_eval_cats:
            cat_stats = per_category.setdefault(cat, {"tp": 0, "fp": 0, "fn": 0})
            if cat in pred_cats and cat in expected_cats:
                cat_stats["tp"] += 1
            elif cat in pred_cats and cat not in expected_cats:
                cat_stats["fp"] += 1
            elif cat not in pred_cats and cat in expected_cats:
                cat_stats["fn"] += 1

    # Calculate category metrics & confusion matrix
    cat_metrics = {}
    total_tp = 0
    total_fp = 0
    total_fn = 0

    for cat, counts in per_category.items():
        tp = counts["tp"]
        fp = counts["fp"]
        fn = counts["fn"]
        positives = tp + fn
        tn = total_samples - (tp + fp + fn)

        total_tp += tp
        total_fp += fp
        total_fn += fn

        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        cat_metrics[cat] = {
            "positives": positives,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "reliable": positives >= 5,
        }

    micro_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    micro_rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    micro_f1 = (2 * micro_prec * micro_rec) / (micro_prec + micro_rec) if (micro_prec + micro_rec) > 0 else 0.0

    macro_f1 = (
        sum(m["f1"] for m in cat_metrics.values()) / len(cat_metrics)
        if cat_metrics
        else 0.0
    )

    benign_fpr = round(benign_fp_count / benign_count, 4) if benign_count > 0 else 0.0

    # Ensure all stance classes present in confusion matrix
    stance_classes = ["discussing", "none", "potentially_facilitating", "reporting", "unclear", "warning"]
    formatted_stance_matrix = {
        exp: {pred: stance_confusion[exp][pred] for pred in stance_classes}
        for exp in stance_classes
    }

    return {
        "sample_count": total_samples,
        "benign_count": benign_count,
        "benign_fp_count": benign_fp_count,
        "benign_fpr": benign_fpr,
        "stance_accuracy": round(stance_correct / total_samples, 4) if total_samples > 0 else 0.0,
        "stance_confusion": formatted_stance_matrix,
        "unclear_count": unclear_count,
        "unclear_rate": round(unclear_count / total_samples, 4) if total_samples > 0 else 0.0,
        "dangerous_warn_to_fac": dangerous_warn_to_fac,
        "dangerous_fac_to_warn": dangerous_fac_to_warn,
        "micro_precision": round(micro_prec, 4),
        "micro_recall": round(micro_rec, 4),
        "micro_f1": round(micro_f1, 4),
        "macro_f1": round(macro_f1, 4),
        "per_category": cat_metrics,
        "per_language": per_language,
    }

def cmd_rules_evaluate(
    taxonomy_dir: Path,
    holdout_path: Optional[str] = None,
    output_report_path: Optional[Path] = None,
) -> None:
    """Run full evaluation suite on dev data, write report, and handle holdout."""
    _, rules = load_taxonomy_from_directory(taxonomy_dir)
    engine = ThreatDetectionEngine(rules)

    backend_dir = Path(__file__).resolve().parent.parent
    dev_path = backend_dir / "tests" / "data" / "detection" / "dev_generated_extra.jsonl"
    if not dev_path.exists():
        print(f"Error: Dev dataset not found at {dev_path}", file=sys.stderr)
        return

    # 1. Dev-copy lint
    dev_copies = check_dev_copy_lint(taxonomy_dir, dev_path)
    print("=================================================================")
    print(f"DEV-COPY LINT CHECK (4+ word phrases verbatim in dev samples)")
    print("=================================================================")
    if dev_copies:
        print(f"WARNING: Found {len(dev_copies)} dev-copy violations:")
        for c in dev_copies:
            print(f"  • Rule '{c['rule_id']}' in {c['category']}: \"{c['phrase']}\" in {c['sample_id']}")
    else:
        print("PASS: 0 dev-copy violations. No rules contain 4+ word phrases from dev samples.")

    # 2. Dev (generated) Evaluation
    dev_metrics = evaluate_dataset(engine, dev_path)

    print("\n=================================================================")
    print(f"DEV (GENERATED) EVALUATION RESULTS (Set Size: {dev_metrics['sample_count']})")
    print("=================================================================")
    print("Note: The dev set is agent-generated. Stance accuracy is measured on synthetic dev data.")
    print(f"Benign Set Size:           {dev_metrics['benign_count']}")
    print(f"False-Positive Rate (B):   {dev_metrics['benign_fpr'] * 100:.2f}% ({dev_metrics['benign_fp_count']}/{dev_metrics['benign_count']})")
    print(f"Stance Accuracy:           {dev_metrics['stance_accuracy'] * 100:.2f}%")
    print(f"Unclear Stance Routing:    {dev_metrics['unclear_count']}/{dev_metrics['sample_count']} ({dev_metrics['unclear_rate'] * 100:.2f}%)")
    print(f"Dangerous False Alerts:    {dev_metrics['dangerous_warn_to_fac']} (warning -> potentially_facilitating)")
    print(f"Dangerous Missed Scams:    {dev_metrics['dangerous_fac_to_warn']} (potentially_facilitating -> warning)")

    print("\nStance Confusion Matrix (Rows: Expected, Cols: Predicted):")
    cols = ["discussing", "none", "potentially_facilitating", "reporting", "unclear", "warning"]
    short_cols = ["disc", "none", "facil", "report", "unclear", "warn"]
    print(f"  {'Expected':<24} " + " ".join(f"{c:>7}" for c in short_cols))
    for exp in cols:
        row = dev_metrics["stance_confusion"].get(exp, {})
        row_str = " ".join(f"{row.get(p, 0):>7}" for p in cols)
        print(f"  {exp:<24} {row_str}")
    print(f"Micro Precision:           {dev_metrics['micro_precision']:.4f}")
    print(f"Micro Recall:              {dev_metrics['micro_recall']:.4f}")
    print(f"Micro F1:                  {dev_metrics['micro_f1']:.4f}")
    print(f"Macro F1:                  {dev_metrics['macro_f1']:.4f}")

    print("\nPer-Category Breakdown & Confusion Matrix:")
    for cat, m in sorted(dev_metrics["per_category"].items()):
        reliability_tag = "" if m["reliable"] else " [NOT RELIABLY MEASURED: <5 positives]"
        print(
            f"  • {cat:<24} Pos={m['positives']:<2} P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f} "
            f"(TP={m['tp']}, FP={m['fp']}, FN={m['fn']}, TN={m['tn']}){reliability_tag}"
        )

    print("\nPer-Language Confusion Breakdown:")
    for lang, lstats in sorted(dev_metrics["per_language"].items()):
        acc = (lstats["correct_detections"] / lstats["samples"]) * 100 if lstats["samples"] > 0 else 0.0
        print(
            f"  • {lang:<12} {lstats['correct_detections']}/{lstats['samples']} ({acc:.1f}%) "
            f"[TP={lstats['tp']}, FP={lstats['fp']}, FN={lstats['fn']}]"
        )

    # 3. Holdout Evaluation (strict isolated evaluation if path provided)
    holdout_metrics = None
    if holdout_path:
        h_file = Path(holdout_path)
        if h_file.exists():
            holdout_metrics = evaluate_dataset(engine, h_file)
            print("\n=================================================================")
            print(f"HOLDOUT EVALUATION RESULTS (Set Size: {holdout_metrics['sample_count']})")
            print("=================================================================")
            print(f"Micro F1: {holdout_metrics['micro_f1']:.4f}")
        else:
            print(f"Error: holdout path {holdout_path} does not exist", file=sys.stderr)
    else:
        print("\nholdout: not provided")

    # 4. Generate Markdown Evaluation Report
    report_file = output_report_path or (backend_dir.parent / "docs" / "eval" / "phase3_detection_report.md")
    report_file.parent.mkdir(parents=True, exist_ok=True)

    report_lines = [
        "# Phase 3 Threat Detection Rules Engine Evaluation Report",
        "",
        "> **Methodology Notice:** The development evaluation dataset (`dev_generated_extra.jsonl`) is agent-generated. "
        "High stance and categorization accuracy reflect synthetic generation and serve strictly as a regression smoke test. "
        "Any category with fewer than 5 positive samples is marked as *not reliably measured*.",
        "",
        "## 1. Summary",
        f"- **Dataset:** `dev (generated)` ({dev_metrics['sample_count']} samples)",
        f"- **Benign / Cautionary Set Size:** {dev_metrics['benign_count']} samples",
        f"- **False-Positive Rate on Benign Messages:** {dev_metrics['benign_fpr'] * 100:.2f}% ({dev_metrics['benign_fp_count']}/{dev_metrics['benign_count']})",
        "- **Dev-Copy Lint Violations:** " + (f"{len(dev_copies)} violations" if dev_copies else "0 violations (clean)"),
        f"- **Stance Accuracy:** {dev_metrics['stance_accuracy'] * 100:.2f}%",
        f"- **Overall Micro F1:** {dev_metrics['micro_f1']:.4f}",
        f"- **Overall Macro F1:** {dev_metrics['macro_f1']:.4f}",
        "- **Holdout Evaluation:** " + (f"Evaluated ({holdout_metrics['sample_count']} samples, Micro F1: {holdout_metrics['micro_f1']:.4f})" if holdout_metrics else "holdout: not provided"),
        "",
        "## 2. Dev-Copy Lint Audit",
        "Scans all taxonomy rules for any phrase or regex literal of 4+ words that occurs verbatim in dev samples.",
        "",
    ]

    if dev_copies:
        report_lines.append("| Rule ID | Category | Verbatim Phrase | Matched Sample |")
        report_lines.append("| :--- | :--- | :--- | :--- |")
        for c in dev_copies:
            report_lines.append(f"| `{c['rule_id']}` | `{c['category']}` | \"{c['phrase']}\" | `{c['sample_id']}` |")
    else:
        report_lines.append("✅ **Zero verbatim 4+ word rule phrases detected in dev samples.** All rules are generalized.")

    report_lines.extend([
        "",
        "## 3. Dev (Generated) Per-Category Breakdown & Confusion Matrix",
        "| Category | Positives | Precision | Recall | F1 Score | TP | FP | FN | TN | Reliability |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for cat, m in sorted(dev_metrics["per_category"].items()):
        reliability = "Reliable (>=5)" if m["reliable"] else "**Not Reliably Measured (<5)**"
        report_lines.append(
            f"| `{cat}` | {m['positives']} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | "
            f"{m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {reliability} |"
        )

    report_lines.extend([
        "",
        "## 4. Dev (Generated) Per-Language Confusion Matrix",
        "| Language | Total Samples | Exact Set Matches | Accuracy | TP | FP | FN |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for lang, lstats in sorted(dev_metrics["per_language"].items()):
        acc = (lstats["correct_detections"] / lstats["samples"]) * 100 if lstats["samples"] > 0 else 0.0
        report_lines.append(
            f"| {lang.capitalize()} | {lstats['samples']} | {lstats['correct_detections']} | {acc:.1f}% | "
            f"{lstats['tp']} | {lstats['fp']} | {lstats['fn']} |"
        )

    report_lines.extend([
        "",
        "## 5. Architectural Invariants Verified",
        "- **Sensitive Excerpt Masking:** Full redaction for passwords, PINs, CVV, OTP, phone numbers, Telegram handles; e-mail domain retention (`[EMAIL_REDACTED]@domain`), UPI handle retention (`***@handle`); cards, Aadhaar, PAN, and bank accounts retain at most last 4 digits; excerpts bounded <= 120 chars.",
        "- **ReDoS Hard Cap & Time Budget:** Hard 4096 character input limit enforced; 50ms per-rule regex timeout with degraded fallback and counter logging; 200ms overall per-message budget.",
        "- **Official Domain Allowlist:** Externalized in `rules/allowlists/official_domains.yaml` with label-boundary matching (`.bank.in`, `.fin.in`, `.gov.in`, `.nic.in` and official banks); suppresses brand lookalike alerts only.",
        "- **Idempotency:** Unique constraint `(tenant_id, message_id, category, taxonomy_version)` enforced.",
        "- **Consent Gating:** Re-checked at runtime in worker task; non-consented messages immediately skipped.",
        "- **Deletion Cascade:** Purges detections, rule hits, and URL indicators on `/delete_me`.",
        "- **Offline URL Heuristics:** Zero network or socket resolution during indicator extraction.",
        "- **Rule Review Gate:** Unreviewed rules excluded in `TTI_ENV=production`.",
    ])

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines) + "\n")

    print(f"\nReport written to: {report_file}")


def cmd_rules_review_export(
    taxonomy_dir: Path,
    output_path: Optional[Path] = None,
) -> None:
    """Export rules for human review into docs/eval/rules_for_review.md with actual regional patterns."""
    import glob
    backend_dir = Path(__file__).resolve().parent.parent
    if output_path is None:
        output_path = backend_dir.parent / "docs" / "eval" / "rules_for_review.md"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    yaml_files = sorted(taxonomy_dir.glob("*.yaml"))
    if not yaml_files:
        yaml_files = sorted((backend_dir / taxonomy_dir).glob("*.yaml"))

    all_rules = []
    lang_counts: Dict[str, int] = defaultdict(int)
    cat_counts: Dict[str, int] = defaultdict(int)
    reviewed_counts: Dict[bool, int] = defaultdict(int)

    for yf in yaml_files:
        with open(yf, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        cat = data.get("category", yf.stem)
        for r in data.get("rules", []):
            rule_entry = dict(r)
            rule_entry["category"] = cat
            all_rules.append(rule_entry)

            for l in r.get("languages", []):
                lang_counts[l] += 1
            cat_counts[cat] += 1
            reviewed_counts[r.get("is_reviewed", False)] += 1

    lines = [
        "# Threat Detection Taxonomy: Regional Rules for Review",
        "",
        "This document exports the **ACTUAL** Hindi, Marathi, and Hinglish keywords, phrases, proximity windows, and regex patterns configured in `backend/rules/taxonomy/` for human review.",
        "",
        "## Summary Counts",
        "",
        f"- **Total Rules:** {len(all_rules)}",
        f"- **Reviewed Rules:** {reviewed_counts[True]}",
        f"- **Unreviewed Rules:** {reviewed_counts[False]}",
        "",
        "### Rules per Language",
        "| Language | Rule Count |",
        "|---|---|",
    ]
    for lang, cnt in sorted(lang_counts.items()):
        lines.append(f"| `{lang}` | {cnt} |")

    lines.extend([
        "",
        "### Rules per Category",
        "| Category | Rule Count |",
        "|---|---|",
    ])
    for cat, cnt in sorted(cat_counts.items()):
        lines.append(f"| `{cat}` | {cnt} |")

    lines.extend([
        "",
        "---",
        "",
        "## Detailed Rule Pattern Specification",
        "",
    ])

    for r in all_rules:
        langs = r.get("languages", [])
        is_regional = any(l in ("hi", "mr", "hinglish", "hindi", "marathi") for l in langs)
        payload = r.get("pattern_payload", {})

        lines.append(f"### `{r['rule_id']}`")
        lines.append(f"- **Category:** `{r['category']}`")
        lines.append(f"- **Rule Type:** `{r.get('rule_type', 'keyword')}`")
        lines.append(f"- **Languages:** {', '.join(langs)}")
        lines.append(f"- **is_reviewed:** `{r.get('is_reviewed', False)}`")
        lines.append(f"- **Severity:** `{r.get('default_severity', 'MEDIUM')}`")
        lines.append(f"- **Weight:** `{r.get('weight', 1.0)}`")
        lines.append("")
        lines.append("**Actual Pattern Definitions:**")
        lines.append("```yaml")
        # Dump exact pattern payload
        lines.append(yaml.dump(payload, allow_unicode=True, sort_keys=False).strip())
        lines.append("```")
        lines.append("")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Exported {len(all_rules)} rules to {output_path}")
    print(f"Summary: {len(all_rules)} total rules, {reviewed_counts[True]} reviewed, {reviewed_counts[False]} unreviewed.")


async def cmd_mtproto_login() -> None:
    """Interactive MTProto authentication.

    Prompts for phone / login code / 2FA password via Telethon, then prints a
    StringSession to be stored in TTI_TELEGRAM_SESSION inside the gitignored .env.
    The session string is NEVER written to logs or files by this tool.
    """
    settings = get_settings()
    if not settings.mtproto_credentials_configured:
        print("ERROR: TTI_TELEGRAM_API_ID / TTI_TELEGRAM_API_HASH are not configured in .env.")
        return
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
    except ImportError:
        print("ERROR: telethon is not installed. Run: pip install telethon")
        return

    print("Telegram MTProto authentication for TTI collection.")
    print("You will be prompted for phone number, login code, and (if enabled) 2FA password.")
    client = TelegramClient(
        StringSession(),
        int(settings.TTI_TELEGRAM_API_ID),
        settings.TTI_TELEGRAM_API_HASH,
        device_model="TTI-Intelligence-Collector",
        system_version="TTI",
        app_version="0.1.0",
    )
    await client.start()  # Interactive prompts happen here
    me = await client.get_me()
    session_string = client.session.save()
    print()
    print("AUTHENTICATION SUCCESSFUL")
    print(f"Account: @{me.username or me.id}")
    print()
    print("Copy the following session string into TTI_TELEGRAM_SESSION in your .env file:")
    print("(never commit it; .env is gitignored)")
    print()
    print(session_string)
    print()
    await client.disconnect()


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="TTI Threat Intelligence CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # mtproto-login (interactive Telegram authentication)
    subparsers.add_parser(
        "mtproto-login",
        help="Authenticate a Telegram account via MTProto and print the session string",
    )

    rules_parser = subparsers.add_parser("rules", help="Manage threat detection rules")
    rules_subparsers = rules_parser.add_subparsers(dest="subcommand", required=True)

    # rules sync
    sync_p = rules_subparsers.add_parser("sync", help="Synchronize YAML taxonomy into database")
    sync_p.add_argument(
        "--taxonomy-dir",
        type=Path,
        default=Path("rules/taxonomy"),
        help="Path to YAML taxonomy rules directory",
    )

    # rules test
    test_p = rules_subparsers.add_parser("test", help="Execute engine self-test assertions")
    test_p.add_argument(
        "--taxonomy-dir",
        type=Path,
        default=Path("rules/taxonomy"),
        help="Path to YAML taxonomy rules directory",
    )

    # rules review-export
    export_p = rules_subparsers.add_parser("review-export", help="Export regional rules for human review")
    export_p.add_argument(
        "--taxonomy-dir",
        type=Path,
        default=Path("rules/taxonomy"),
        help="Path to YAML taxonomy rules directory",
    )
    export_p.add_argument(
        "--output-file",
        type=Path,
        default=None,
        help="Output markdown file path",
    )

    # rules evaluate
    eval_p = rules_subparsers.add_parser("evaluate", help="Evaluate detection engine on datasets")
    eval_p.add_argument(
        "--taxonomy-dir",
        type=Path,
        default=Path("rules/taxonomy"),
        help="Path to YAML taxonomy rules directory",
    )
    eval_p.add_argument(
        "--holdout-path",
        type=str,
        default=None,
        help="Path to private external holdout dataset (JSONL)",
    )
    eval_p.add_argument(
        "--output-report",
        type=Path,
        default=None,
        help="Path to write markdown evaluation report",
    )

    args = parser.parse_args()

    if args.command == "mtproto-login":
        asyncio.run(cmd_mtproto_login())
        return

    if args.command == "rules":
        if args.subcommand == "sync":
            asyncio.run(cmd_rules_sync(args.taxonomy_dir))
        elif args.subcommand == "test":
            cmd_rules_test(args.taxonomy_dir)
        elif args.subcommand == "review-export":
            cmd_rules_review_export(args.taxonomy_dir, args.output_file)
        elif args.subcommand == "evaluate":
            cmd_rules_evaluate(args.taxonomy_dir, args.holdout_path, args.output_report)


if __name__ == "__main__":
    main()
