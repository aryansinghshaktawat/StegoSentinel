/**
 * StegoSentinel Forensic Telemetry TypeScript Interfaces
 */

export interface Finding {
  id: string;
  analysis_id: string;
  type: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;
  description: string;
  evidence?: Record<string, any>;
  analyzer: string;
  analyzer_version: string;
  created_at: string;
}

export interface Candidate {
  id: string;
  analysis_id: string;
  technique: string;
  parameters: Record<string, any>;
  feature_vector?: Record<string, number>;
  raw_score: number;
  ml_score: number;
  validation_score: number;
  final_score: number;
  status: "VALID" | "PARTIAL" | "INVALID" | "UNKNOWN";
  extracted_type?: string;
  printable_ratio?: number;
  validation_description?: string;
  payload_size?: number;
  encoding?: string;
  decode_status: string;
  decoded_text?: string;
  evidence_object_id?: string;
  created_at: string;
}

export interface CandidatePayloadEvidence {
  id: string;
  name: string;
  sha256: string;
  size: number;
  detected_type: string;
  download_url: string;
}

export interface CandidatePayload {
  candidate_id: string;
  analysis_id: string;
  technique: string;
  status: string;
  type?: string;
  payload_size?: number;
  encoding?: string;
  decode_status: string;
  decoded_text?: string;
  evidence_object_id?: string;
  evidence?: CandidatePayloadEvidence;
}

export interface EvidenceObject {
  id: string;
  analysis_id: string;
  parent_id?: string | null;
  name: string;
  sha256: string;
  size: number;
  detected_type: string;
  storage_reference: string;
  extraction_method: string;
  source_offset: number;
  recursion_depth: number;
  created_at: string;
  children?: EvidenceObject[];
  candidate_id?: string;
  decode_status?: string;
  decoded_text?: string;
}

export interface AnalysisSummary {
  id: string;
  user_id?: string;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "RESOURCE_LIMIT";
  original_filename: string;
  sha256: string;
  sha512?: string;
  size: number;
  detected_type: string;
  entropy?: number;
  stego_likelihood?: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
}

export interface AnalysisDetail extends AnalysisSummary {
  findings: Finding[];
  candidates: Candidate[];
  evidence_objects: EvidenceObject[];
}

export interface Report {
  id: string;
  analysis_id: string;
  model: string;
  prompt_version: number;
  result: {
    executive_summary: string;
    stego_likelihood: number;
    findings_evaluated: number;
    evidence_objects_discovered: number;
    analyst_recommendations: string[];
    forensic_limitations: string[];
  };
  markdown_content: string;
  created_at: string;
}

export interface HealthStatus {
  status: string;
  checks: {
    database: { status: string };
    quarantine_storage: { status: string; path?: string };
    redis: { status: string; mode?: string };
    external_tools: Record<string, boolean>;
  };
}
