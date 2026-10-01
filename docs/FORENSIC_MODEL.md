# StegoSentinel: Forensic & Evidence Model

## 1. Evidence Hierarchy & Lineage

StegoSentinel models forensic investigations as a Directed Acyclic Graph (DAG) of **Evidence Objects**:

```
[Original Upload: evidence_0 (Depth 0)]
   │
   ├── [Extracted Payload: evidence_1 (Depth 1, LSB RGB Plane 0)]
   │      │
   │      └── [Uncompressed Archive Member: evidence_2 (Depth 2, ZIP Member)]
   │
   └── [Trailing Overlay: evidence_3 (Depth 1, EOF Marker Offset 0x4A10)]
```

### 1.1 Core Database Entities
- **`Analysis`**: Top-level case session representing the target artifact.
- **`Finding`**: Specific anomaly discovered by an analyzer with severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), confidence score, and raw forensic evidence dictionary.
- **`Candidate`**: Steganographic extraction hypothesis evaluated across channel, bit-plane, stride, and endianness parameters.
- **`EvidenceObject`**: Concrete file or payload extracted from the target, tracked by SHA-256 and recursion depth.
- **`AuditEvent`**: Cryptographically verifiable log of all actions taken against the case.

---

## 2. Forensic Reporting Standards

### 2.1 Terminology Rules
- **Prohibited**: *"This file is guaranteed clean."*
- **Required**: *"No supported steganographic indicators were observed within tested parameters."*
- **Prohibited**: *"Malware found in bit plane 0."*
- **Required**: *"Executable binary payload (PE/ELF magic bytes detected) extracted from bit plane 0."*
- **Prohibited**: *"AI confirmed steganography."*
- **Required**: *"Statistical anomaly model evaluated steganography likelihood at 88% based on Chi-square bit distribution."*

### 2.2 Forensic Chain of Custody
1. **Intake Timestamp**: High-precision UTC timestamp recorded at multipart receipt.
2. **Cryptographic Integrity**: SHA-256 and SHA-512 recorded before any read or parse operation.
3. **Immutability**: Original file is marked read-only.
4. **Reproducibility**: All analyzer versions, model versions, and extraction parameters are stored directly on finding and candidate rows.
