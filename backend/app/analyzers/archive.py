"""
Safe archive forensic analyzer and unpacker for StegoSentinel.
Implements Zip Slip path traversal defense, decompression bomb detection,
symlink neutralizing, and child evidence object extraction.
"""
import io
import os
from pathlib import Path
from typing import List, Tuple
import zipfile
from app.analyzers.base import BaseAnalyzer, AnalysisContext, FindingData
from app.core.limits import LIMITS


class ArchiveAnalyzer(BaseAnalyzer):
    name = "ArchiveAnalyzer"
    version = "1.0.0"

    def can_analyze(self, context: AnalysisContext) -> bool:
        return (
            context.mime_type in ["application/zip", "application/x-zip-compressed"]
            or context.filename.endswith(".zip")
        )

    def analyze(self, context: AnalysisContext) -> List[FindingData]:
        findings: List[FindingData] = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(context.file_bytes))
        except zipfile.BadZipFile as e:
            findings.append(
                FindingData(
                    type="MALFORMED_ZIP_ARCHIVE",
                    severity="MEDIUM",
                    confidence=0.9,
                    description=f"Malformed or corrupted ZIP file structure: {str(e)}",
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )
            return findings

        namelist = zf.namelist()
        total_compressed = sum(info.compress_size for info in zf.infolist())
        total_uncompressed = sum(info.file_size for info in zf.infolist())

        # 1. Archive Inventory Finding
        findings.append(
            FindingData(
                type="ARCHIVE_INVENTORY",
                severity="INFO",
                confidence=1.0,
                description=f"Archive contains {len(namelist)} entries.",
                evidence={
                    "entry_count": len(namelist),
                    "total_compressed": total_compressed,
                    "total_uncompressed": total_uncompressed,
                    "entries": namelist[:20],
                },
                analyzer=self.name,
                analyzer_version=self.version,
            )
        )

        # 2. Decompression Bomb Detection
        if total_compressed > 0:
            ratio = total_uncompressed / total_compressed
            if ratio > LIMITS.MAX_DECOMPRESSION_RATIO:
                findings.append(
                    FindingData(
                        type="ZIP_BOMB_DETECTED",
                        severity="CRITICAL",
                        confidence=0.99,
                        description=(
                            f"Suspiciously high decompression ratio ({ratio:.1f}:1). "
                            f"Exceeds safe threshold of {LIMITS.MAX_DECOMPRESSION_RATIO}:1 (potential zip bomb)."
                        ),
                        evidence={
                            "ratio": round(ratio, 2),
                            "compressed": total_compressed,
                            "uncompressed": total_uncompressed,
                        },
                        analyzer=self.name,
                        analyzer_version=self.version,
                    )
                )
                return findings  # Abort extraction to prevent denial of service

        # 3. Path Traversal (Zip Slip) & Symlink Check
        suspicious_paths = []
        safe_extractable_entries: List[Tuple[zipfile.ZipInfo, bytes]] = []

        cumulative_extracted_size = 0
        extracted_count = 0

        for info in zf.infolist():
            raw_name = info.filename

            # Check path traversal
            if (
                ".." in raw_name
                or raw_name.startswith("/")
                or raw_name.startswith("\\")
                or "\x00" in raw_name
                or os.path.isabs(raw_name)
            ):
                suspicious_paths.append(raw_name)
                continue

            # Check symlink attributes (Unix mode standard)
            # S_IFLNK = 0o120000
            is_symlink = (info.external_attr >> 16) & 0o120000 == 0o120000
            if is_symlink:
                suspicious_paths.append(f"SYMLINK: {raw_name}")
                continue

            # Check per-file size limit
            if info.file_size > LIMITS.MAX_FILE_SIZE_PER_OBJECT:
                findings.append(
                    FindingData(
                        type="ARCHIVE_ENTRY_OVERSIZED",
                        severity="MEDIUM",
                        confidence=1.0,
                        description=f"Entry '{raw_name}' ({info.file_size} bytes) exceeds per-object size limit.",
                        analyzer=self.name,
                        analyzer_version=self.version,
                    )
                )
                continue

            if not info.is_dir():
                if extracted_count >= LIMITS.MAX_EXTRACTED_OBJECTS:
                    findings.append(
                        FindingData(
                            type="ARCHIVE_EXTRACTION_LIMIT_REACHED",
                            severity="LOW",
                            confidence=1.0,
                            description=f"Reached maximum extractable object budget ({LIMITS.MAX_EXTRACTED_OBJECTS}).",
                            analyzer=self.name,
                            analyzer_version=self.version,
                        )
                    )
                    break

                if cumulative_extracted_size + info.file_size > LIMITS.MAX_TOTAL_EXTRACTED_SIZE:
                    findings.append(
                        FindingData(
                            type="ARCHIVE_TOTAL_SIZE_LIMIT_REACHED",
                            severity="LOW",
                            confidence=1.0,
                            description=f"Reached cumulative uncompressed archive budget ({LIMITS.MAX_TOTAL_EXTRACTED_SIZE} bytes).",
                            analyzer=self.name,
                            analyzer_version=self.version,
                        )
                    )
                    break

                try:
                    data = zf.read(info)
                    safe_extractable_entries.append((info, data))
                    cumulative_extracted_size += len(data)
                    extracted_count += 1
                except Exception as e:
                    findings.append(
                        FindingData(
                            type="ARCHIVE_ENTRY_READ_ERROR",
                            severity="LOW",
                            confidence=0.8,
                            description=f"Failed to read entry {raw_name}: {str(e)}",
                            analyzer=self.name,
                            analyzer_version=self.version,
                        )
                    )

        if suspicious_paths:
            findings.append(
                FindingData(
                    type="ZIP_PATH_TRAVERSAL_ATTACK",
                    severity="CRITICAL",
                    confidence=1.0,
                    description=f"Discovered {len(suspicious_paths)} entries attempting path traversal or symlink redirection.",
                    evidence={"traversal_paths": suspicious_paths},
                    analyzer=self.name,
                    analyzer_version=self.version,
                )
            )

        # Attach safe extracted entries to context for recursive ingestion
        context.metadata["extracted_archive_members"] = safe_extractable_entries

        return findings
