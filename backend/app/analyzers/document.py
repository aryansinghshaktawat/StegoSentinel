"""
Document forensic analyzer for StegoSentinel (PDF, DOCX, XLSX, PPTX).
Safely inspects PDF dictionaries and streams, Office OOXML relationships,
macros, and embedded payloads without executing scripts or macros.
"""

import io
import re
import zipfile

from app.analyzers.base import AnalysisContext, BaseAnalyzer, FindingData


class DocumentAnalyzer(BaseAnalyzer):
    name = "DocumentAnalyzer"
    version = "1.0.0"

    def can_analyze(self, context: AnalysisContext) -> bool:
        return context.mime_type == "application/pdf" or context.filename.endswith(
            (".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls")
        )

    def analyze(self, context: AnalysisContext) -> list[FindingData]:
        findings: list[FindingData] = []
        if context.mime_type == "application/pdf" or context.filename.endswith(".pdf"):
            findings.extend(self._analyze_pdf(context))
        elif context.filename.endswith((".docx", ".xlsx", ".pptx")):
            findings.extend(self._analyze_office_ooxml(context))
        return findings

    def _analyze_pdf(self, context: AnalysisContext) -> list[FindingData]:
        findings = []
        data = context.file_bytes

        # PDF Version check
        ver_match = re.search(rb"%PDF-(\d+\.\d+)", data[:1024])
        pdf_version = ver_match.group(1).decode("ascii") if ver_match else "Unknown"

        findings.append(
            FindingData(
                type="PDF_METADATA",
                severity="INFO",
                confidence=1.0,
                description=f"Identified PDF Document (version {pdf_version}).",
                evidence={"pdf_version": pdf_version},
                analyzer=self.name,
                analyzer_version=self.version,
            )
        )

        # Suspicious PDF objects scanner
        suspicious_tags = [
            (
                rb"/JavaScript",
                "PDF_JAVASCRIPT_STREAM",
                "HIGH",
                "Contains embedded JavaScript object.",
            ),
            (rb"/JS", "PDF_JS_KEYWORD", "HIGH", "Contains /JS script reference."),
            (
                rb"/Launch",
                "PDF_LAUNCH_ACTION",
                "CRITICAL",
                "Contains /Launch external execution action.",
            ),
            (
                rb"/EmbeddedFiles",
                "PDF_EMBEDDED_FILES",
                "HIGH",
                "Contains embedded external file attachments.",
            ),
            (
                rb"/OpenAction",
                "PDF_OPEN_ACTION",
                "MEDIUM",
                "Configured with automatic /OpenAction trigger.",
            ),
        ]

        for tag, ftype, severity, desc in suspicious_tags:
            count = len(re.findall(tag, data))
            if count > 0:
                findings.append(
                    FindingData(
                        type=ftype,
                        severity=severity,
                        confidence=0.95,
                        description=f"{desc} (found {count} occurrence(s)).",
                        evidence={"tag": tag.decode("latin-1"), "count": count},
                        analyzer=self.name,
                        analyzer_version=self.version,
                    )
                )

        return findings

    def _analyze_office_ooxml(self, context: AnalysisContext) -> list[FindingData]:
        findings = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(context.file_bytes))
            namelist = zf.namelist()
        except Exception:
            return findings

        # Check for VBA Macros
        macro_entries = [name for name in namelist if "vbaProject.bin" in name.lower()]
        if macro_entries:
            findings.append(
                FindingData(
                    type="OFFICE_VBA_MACRO_DETECTED",
                    severity="HIGH",
                    confidence=0.99,
                    description="Office document contains embedded VBA macros (vbaProject.bin).",
                    evidence={"macro_entries": macro_entries},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        # Check for external relationships (OLE / Template Injection)
        external_rels = []
        for name in namelist:
            if name.endswith(".rels"):
                try:
                    rel_content = zf.read(name).decode("utf-8", errors="replace")
                    if 'TargetMode="External"' in rel_content:
                        external_rels.append(name)
                except Exception:
                    pass

        if external_rels:
            findings.append(
                FindingData(
                    type="OFFICE_EXTERNAL_RELATIONSHIPS",
                    severity="HIGH",
                    confidence=0.9,
                    description="Document references external network resources / templates (possible template injection).",
                    evidence={"relationship_files": external_rels},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        return findings
