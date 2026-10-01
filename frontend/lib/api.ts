import {
  AnalysisDetail,
  AnalysisSummary,
  CandidatePayload,
  EvidenceObject,
  HealthStatus,
  Report,
} from "@/types";

const API_BASE = "/api/v1";

const parseErrorMessage = async (response: Response): Promise<string> => {
  const contentType = response.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    const payload = (await response.json()) as { detail?: string };
    if (payload?.detail) {
      return payload.detail;
    }
  } else {
    const text = await response.text();
    if (text) {
      return text;
    }
  }

  return `Request failed with status ${response.status}`;
};

const request = async <T>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    throw new Error(await parseErrorMessage(response));
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return (await response.json()) as T;
  }

  return (await response.text()) as T;
};

export const api = {
  async uploadFile(file: File, maxCandidates = 100): Promise<AnalysisSummary> {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("max_candidates", String(maxCandidates));
    formData.append("generate_report", "true");

    return request<AnalysisSummary>("/analyses", {
      method: "POST",
      body: formData,
    });
  },

  getAnalyses(): Promise<AnalysisSummary[]> {
    return request<AnalysisSummary[]>("/analyses");
  },

  getAnalysis(analysisId: string): Promise<AnalysisDetail> {
    return request<AnalysisDetail>(`/analyses/${encodeURIComponent(analysisId)}`);
  },

  getEvidenceTree(analysisId: string): Promise<EvidenceObject[]> {
    return request<EvidenceObject[]>(`/analyses/${encodeURIComponent(analysisId)}/evidence`);
  },

  getCandidatePayload(analysisId: string, candidateId: string): Promise<CandidatePayload> {
    return request<CandidatePayload>(
      `/analyses/${encodeURIComponent(analysisId)}/candidates/${encodeURIComponent(candidateId)}/payload`
    );
  },

  getReport(analysisId: string, format: "json" | "markdown" = "json"): Promise<Report | string> {
    return request<Report | string>(
      `/analyses/${encodeURIComponent(analysisId)}/report?format=${encodeURIComponent(format)}`
    );
  },

  getHealth(): Promise<HealthStatus> {
    return request<HealthStatus>("/health/ready");
  },

  getDownloadUrl(evidenceId: string): string {
    return `${API_BASE}/evidence/${encodeURIComponent(evidenceId)}/download`;
  },
};
