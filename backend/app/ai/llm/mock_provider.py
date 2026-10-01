"""
Deterministic Mock LLM Provider for StegoSentinel.
Produces defensible, rule-based forensic summaries and briefings offline without external API keys.
"""

from typing import Any

from app.ai.llm.provider import LLMProvider


class MockLLMProvider(LLMProvider):
    def generate_summary(self, evidence_summary: dict[str, Any]) -> dict[str, Any]:
        filename = evidence_summary.get("original_filename", "unnamed_artifact")
        stego_likelihood = evidence_summary.get("stego_likelihood", 0.0)
        findings_count = len(evidence_summary.get("findings", []))
        top_candidate = evidence_summary.get("top_candidate")
        extracted_objects = evidence_summary.get("extracted_objects_count", 0)

        # Formulate executive narrative using strict defensible terminology
        if stego_likelihood >= 0.70:
            narrative = (
                f"Automated forensic triage for '{filename}' identified strong statistical and structural anomalies "
                f"(Steganography likelihood: {int(stego_likelihood * 100)}%). "
                f"Evaluation detected {findings_count} anomalous indicators across tested bit-planes and channels. "
            )
            if top_candidate:
                narrative += (
                    f"Candidate extraction using technique '{top_candidate.get('technique')}' yielded "
                    f"a valid structured payload ({top_candidate.get('extracted_type')}). "
                )
        elif stego_likelihood >= 0.40:
            narrative = (
                f"Forensic triage for '{filename}' revealed moderate anomalies (Steganography likelihood: {int(stego_likelihood * 100)}%). "
                f"Observed minor bit-plane or entropy deviations, but no high-confidence deterministic payload was isolated."
            )
        else:
            narrative = (
                f"Forensic evaluation for '{filename}' did not detect significant steganographic indicators "
                f"within tested parameters (Steganography likelihood: {int(stego_likelihood * 100)}%). "
                f"Notice: This does not prove the absence of hidden data, as custom or encrypted covert channels may evade detection."
            )

        return {
            "executive_summary": narrative,
            "stego_likelihood": stego_likelihood,
            "findings_evaluated": findings_count,
            "evidence_objects_discovered": extracted_objects,
            "analyst_recommendations": [
                "Preserve original cryptographic hash chain of custody.",
                "Review extracted evidence objects in isolated quarantine sandbox.",
                "Correlate candidate bitstreams against known threat actor signature databases.",
            ],
            "forensic_limitations": [
                "Steganalysis models are probabilistic; scores do not constitute mathematical certainty.",
                "Encrypted payloads with uniform entropy cannot be decoded without pre-shared keys.",
                "Non-standard proprietary steganography tools may evade automated heuristic parsers.",
            ],
        }

    def generate_markdown_report(self, evidence_summary: dict[str, Any]) -> str:
        summary_data = self.generate_summary(evidence_summary)
        filename = evidence_summary.get("original_filename", "Unknown")
        sha256 = evidence_summary.get("sha256", "Unknown")
        mime = evidence_summary.get("detected_type", "Unknown")
        likelihood = int(evidence_summary.get("stego_likelihood", 0.0) * 100)
        findings = evidence_summary.get("findings", [])
        candidates = evidence_summary.get("candidates", [])
        evidence_objs = evidence_summary.get("evidence_objects", [])

        md = f"""# StegoSentinel Forensic Analysis Report

## 1. Executive Summary
{summary_data["executive_summary"]}

- **Target File**: `{filename}`
- **SHA-256 Digest**: `{sha256}`
- **Identified MIME Type**: `{mime}`
- **Evaluated Steganography Likelihood**: **{likelihood}%**

---

## 2. Key Forensic Findings ({len(findings)})
| Severity | Type | Analyzer | Description |
|---|---|---|---|
"""
        for f in findings[:15]:
            sev = f.get("severity", "INFO")
            ftype = f.get("type", "UNKNOWN")
            anz = f.get("analyzer", "Base")
            desc = f.get("description", "").replace("\n", " ")
            md += f"| **{sev}** | `{ftype}` | {anz} | {desc} |\n"

        md += f"""
---

## 3. Extraction Candidates Evaluated ({len(candidates)})
| Technique | Extracted Type | ML Score | Validation | Final Score | Status |
|---|---|---|---|---|---|
"""
        for c in candidates[:10]:
            tech = c.get("technique", "UNKNOWN")
            etype = c.get("extracted_type", "unknown")
            ml = f"{c.get('ml_score', 0.0):.2f}"
            val = f"{c.get('validation_score', 0.0):.2f}"
            fn = f"{c.get('final_score', 0.0):.2f}"
            st = c.get("status", "UNKNOWN")
            md += f"| `{tech}` | {etype} | {ml} | {val} | **{fn}** | `{st}` |\n"

        md += f"""
---

## 4. Extracted Evidence Hierarchy ({len(evidence_objs)})
"""
        for eo in evidence_objs:
            depth_indent = "  " * eo.get("recursion_depth", 0)
            md += f"{depth_indent}- **{eo.get('name')}** (`{eo.get('detected_type')}`), Size: {eo.get('size')} bytes, Method: `{eo.get('extraction_method')}`, SHA-256: `{eo.get('sha256')[:16]}...`\n"

        md += """
---

## 5. Forensic Limitations & Defensive Disclaimers
1. **No Absolute Cleanliness Proof**: The absence of findings indicates that supported techniques did not detect hidden data; it does not prove the file is free of covert communication.
2. **Encrypted Channels**: Covert channels using strong encryption (AES, ChaCha20) present as high entropy and cannot be recovered without cryptographic keys.
3. **Probabilistic Scoring**: Steganography likelihood scores represent statistical hypothesis confidence, not legal certainty.

*Report generated by StegoSentinel Engine v1.0.0*
"""
        return md
