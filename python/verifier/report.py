"""Human report, JSON report and the plain-words explanations. ASCII only (safe on any terminal)."""
import json

from .model import ALL_RULES, CANNOT, MATCH, MISMATCH, RULES, RULE_TITLES, WARNING, display

HEADLINE = "LogSabha verification report - consistency evidence from tamper-evident logs"

# One plain-words reason per (rule, result). No jargon without a short gloss.
EXPLAIN = {
    ("I1", MATCH): "Every log entry carries a fingerprint (a hash) of its own content and of the entry before it. "
                   "We recomputed all of them and they agree, so the entries form one unbroken chain.",
    ("I1", MISMATCH): "An entry's content no longer matches its own fingerprint, or it does not point at the entry "
                      "before it. That means the entry was changed after it was written. The exact entry number is in the finding.",
    ("I1", CANNOT): "There was nothing to check the chain on, so we cannot say. Missing evidence is never counted as a match.",
    ("I2", MATCH): "Every signature in the bundle was made by the key that the chain says belongs to that witness.",
    ("I2", MISMATCH): "Something is signed with a different key than the one registered on the chain for that witness, "
                      "or the signature is damaged. So it was not signed by the registered witness.",
    ("I2", CANNOT): "We could not look up a registered key on the chain for some signer, so those signatures stay unchecked.",
    ("I3", MATCH): "The chain holds a short fingerprint (a root) of each batch of entries the witness reported. "
                   "We rebuilt those fingerprints from the bundle and they are identical.",
    ("I3", MISMATCH): "The chain says a batch of entries looked a certain way at a certain time. The bundle does not "
                      "reproduce that: entries are missing or different. Even a log rebuilt with the witness's own key cannot change what the chain already holds.",
    ("I3", CANNOT): "There is no bundle (or no anchor) to compare with the chain, so we cannot say either way.",
    ("I4", MATCH): "The entry numbers run 1, 2, 3 with no holes. Any hole that exists is explained by a signed restart marker, which is listed as a notice.",
    ("I4", MISMATCH): "Some entry numbers are missing in the middle of the log and nothing signed explains why. Entries were removed, or lost.",
    ("I4", CANNOT): "There were no entries to look at, so we cannot say.",
    ("I5", MATCH): "The other witnesses each hold small signed notes (authenticators) about this witness's newest entry at the time. "
                   "All of this witness's entries are covered by such notes, so others saw the same log.",
    ("I5", MISMATCH): "Another witness holds a signed note about an entry that this log no longer has or now shows differently (deleted or changed), "
                      "or the log has an entry no other witness ever saw even though they were answering (likely forged).",
    ("I5", CANNOT): "Not enough witnesses sent evidence, or nobody was reachable after those entries, so we cannot say if others saw them.",
    ("I6", MATCH): "Every receipt this witness gave to another witness is inside the receipts fingerprint that was put on the chain.",
    ("I6", MISMATCH): "A receipt this witness signed (the other witness still holds it) is not inside the receipts fingerprint on the chain. "
                      "So the log was changed after the receipt was given.",
    ("I6", CANNOT): "The receipts could not be placed in an anchored window, so we cannot say.",
    ("I7", MATCH): "No witness signed two different versions of the same batch.",
    ("I7", MISMATCH): "One witness signed two different headers for the same batch number. A witness should only ever sign one.",
    ("I7", CANNOT): "We did not see enough headers to rule out a second version.",
}

EXPLAIN.update({
    ("C1", MATCH): "Every big transfer the Network witness saw leaving has an App witness event for the same request, size and place, "
                   "written close in time. Two witnesses watching different things tell the same story.",
    ("C1", MISMATCH): "The Network witness saw a big transfer leave, but the App witness (which was keeping its log at that time) has no event for it. "
                      "Either the app did not log it, or its record was removed.",
    ("C1", CANNOT): "We cannot tell: the App witness was not keeping signed batches over that time, or its bundle or the policy is missing.",
    ("C2", MATCH): "Every outbound call the App witness logged has a Network witness event for the same request, size and place.",
    ("C2", MISMATCH): "The App witness logged an outbound call, but the Network witness (which was watching at that time) saw nothing. "
                      "Either the call never left, or the network record is missing.",
    ("C2", CANNOT): "We cannot tell: the Network witness was not keeping signed batches over that time, or its bundle or the policy is missing.",
    ("C3", MATCH): "The Outside witness, watching from another place, counted the same bytes per destination as the Network witness, within the allowed tolerance.",
    ("C3", MISMATCH): "The Outside witness counted a different number of bytes to a destination than the Network witness did.",
    ("C3", CANNOT): "The Outside witness's evidence cannot be used as an independent second view (it is missing, not covering that time, or looks copied from the Network witness).",
    ("C4", MATCH): "The witness kept anchoring on the chain, with no quiet stretch longer than the chain allows. Planned pauses are not counted as silence.",
    ("C4", CANNOT): "The witness went quiet for longer than the chain allows, or was flagged silent on the chain. Silence is never treated as proof of anything: it only means we have no evidence for that time.",
    ("C6", WARNING): "A prompt to look at something. It does not change the result.",
})

ANSWER = {
    WARNING: "No answer is required for the verdict; someone should look at it.",
    MATCH: "Nothing to answer: the evidence agrees.",
    MISMATCH: "The witness named under 'Answerable by' should be asked to explain this difference.",
    CANNOT: "More evidence is needed (for example the missing bundle) before this can be decided.",
}


def explain_text(finding):
    base = EXPLAIN.get((finding.rule, finding.result), "")
    return "%s %s" % (base, ANSWER[finding.result]) if base else ANSWER[finding.result]


def finding_lines(f, explain=False, indent="  "):
    out = ["%s - %s" % (f.id, f.statement),
           "%sResult:        %s" % (indent, f.result),
           "%sRule:          %s - %s" % (indent, f.rule, RULE_TITLES.get(f.rule, "")),
           "%sWitnesses:     %s" % (indent, ", ".join(display(w) for w in (f.witnesses or [f.subject]) if w) or "none"),
           "%sTime range:    %s" % (indent, f.time_range)]
    if f.evidence:
        out.append("%sEvidence:" % indent)
        out += ["%s  - %s" % (indent, e) for e in f.evidence]
    else:
        out.append("%sEvidence:      none" % indent)
    out.append("%sLimitation:    %s" % (indent, f.limitation or "none stated"))
    if f.rule in ("C1", "C2", "C3", "C6") and f.policy_version:
        out.append("%sPolicy version: %s" % (indent, f.policy_version))
    out.append("%sAnchor tx:     %s" % (indent, f.anchor_tx or "none"))
    out.append("%sAnswerable by: %s" % (indent, f.answerable_by or "n/a"))
    if explain:
        out.append("%sIn plain words: %s" % (indent, explain_text(f)))
    return out


def human_report(report, explain=False, show_all=False):
    run = report.run
    subjects = run.subjects()
    out = [HEADLINE, "=" * len(HEADLINE),
           "Chain read through: %s" % run.reader.description,
           "Bundles used: %s" % (", ".join(display(w) for w in sorted(run.bundles, key=lambda x: (x not in subjects, x)))
                                 or "none"),
           "Expected on the chain: %s" % (", ".join(display(w) for w in run.registered) or "unknown (chain not readable)"),
           "", "Overall: %s (exit code %d)" % (report.overall, report.exit_code), ""]
    width = max([len(display(w)) for w in subjects] + [14])
    out.append("%-6s %s" % ("Rule", "  ".join(display(w).ljust(width) for w in subjects)))
    matrix = report.matrix()
    for rule, row in matrix.items():
        out.append("%-6s %s   %s" % (rule, "  ".join((row.get(w) or "-").ljust(width) for w in subjects), RULE_TITLES[rule]))
    if any(r in report.selected for r in ("C1", "C2", "C3", "C6")):
        out += ["", "Policy: %s" % run.policy_label, "  %s" % run.policy_note]
    shown = [f for f in report.findings if show_all or f.result != MATCH]
    out += ["", "Findings that are not MATCH: %d" % len([f for f in report.findings if f.result != MATCH]), ""]
    for f in shown:
        out += finding_lines(f, explain)
        out.append("")
    if "C6" in report.selected:
        out += ["Warnings (they do not change the result or the exit code): %d" % len(report.warnings), ""]
        for f in report.warnings:
            out += finding_lines(f, explain)
            out.append("")
    if report.notices:
        out.append("Notices:")
        out += ["  - %s" % n for n in report.notices]
        out.append("")
    out.append("This is consistency evidence from the files and chain data supplied. It does not say who is at fault.")
    out.append("Run again with --finding F-NNNN --explain for one finding in plain words, or --json for a machine-readable report.")
    return "\n".join(out)


def finding_report(f, explain=True):
    return "\n".join(finding_lines(f, explain))


def json_report(report):
    run = report.run
    return json.dumps({
        "overall": report.overall,
        "exit_code": report.exit_code,
        "chain": run.reader.description,
        "chain_error": run.chain_error,
        "expected_witnesses": run.registered,
        "bundles": sorted(run.bundles),
        "unused_inputs": [{"file": p, "why": why} for p, why in report.bundle_notes],
        "matrix": report.matrix(),
        "findings": [f.to_dict() for f in report.findings],
        "warnings": [f.to_dict() for f in report.warnings],
        "warning_count": len(report.warnings),
        "policy": {"label": run.policy_label, "state": run.policy_state, "note": run.policy_note},
        "notices": report.notices,
    }, indent=2, sort_keys=True)
