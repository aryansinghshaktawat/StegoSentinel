"use client";

import { useState, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  UploadCloud,
  FileCheck,
  AlertTriangle,
  FileText,
  Shield,
  Loader2,
  CheckCircle2,
} from "lucide-react";
import { api } from "@/lib/api";

export default function UploadPage() {
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileSha256, setFileSha256] = useState<string>("");
  const [calculatingHash, setCalculatingHash] = useState<boolean>(false);
  const [maxCandidates, setMaxCandidates] = useState<number>(100);
  const [uploading, setUploading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState<boolean>(false);

  const computeSha256 = async (file: File) => {
    try {
      setCalculatingHash(true);
      const buffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      setFileSha256(hashHex);
    } catch {
      setFileSha256("Computed server-side upon quarantine intake");
    } finally {
      setCalculatingHash(false);
    }
  };

  const handleFileSelect = (file: File) => {
    setError(null);
    if (file.size > 100 * 1024 * 1024) {
      setError("File exceeds maximum allowable size of 100 MB.");
      return;
    }
    setSelectedFile(file);
    computeSha256(file);
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleUploadSubmit = async () => {
    if (!selectedFile) return;

    try {
      setUploading(true);
      setError(null);
      const analysis = await api.uploadFile(selectedFile, maxCandidates);
      router.push(`/analysis/${analysis.id}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to quarantine and upload artifact.";
      setError(msg);
      setUploading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      <div className="border-b border-cyber-border pb-6">
        <h1 className="text-3xl font-extrabold tracking-tight text-white font-mono">
          ARTIFACT <span className="text-cyber-cyan">QUARANTINE INTAKE</span>
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Submit untrusted binaries, images, audio, or archives for multi-layer steganalysis and extraction.
        </p>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-cyber-red/10 border border-cyber-red/30 flex items-start gap-3 text-cyber-red font-mono text-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-bold">Intake Refused</p>
            <p className="text-xs text-red-300 mt-1">{error}</p>
          </div>
        </div>
      )}

      {/* Drag & Drop Zone */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all ${
          dragActive
            ? "border-cyber-cyan bg-cyber-cyan/10 glow-cyan"
            : selectedFile
            ? "border-cyber-green/50 bg-cyber-green/5"
            : "border-cyber-border bg-cyber-card hover:border-slate-600 hover:bg-slate-900/50"
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFileSelect(e.target.files[0]);
            }
          }}
        />

        <div className="flex flex-col items-center justify-center space-y-4">
          <div
            className={`p-4 rounded-2xl ${
              selectedFile
                ? "bg-cyber-green/20 text-cyber-green border border-cyber-green/40"
                : "bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30"
            }`}
          >
            {selectedFile ? (
              <FileCheck className="w-8 h-8" />
            ) : (
              <UploadCloud className="w-8 h-8" />
            )}
          </div>

          <div>
            <p className="text-base font-bold text-white font-mono">
              {selectedFile ? selectedFile.name : "Drag & drop suspicious artifact here"}
            </p>
            <p className="text-xs text-slate-400 mt-1">
              or click to browse local filesystem (Max: 100 MB)
            </p>
          </div>

          <div className="flex flex-wrap justify-center gap-2 text-[11px] font-mono text-slate-500 pt-2">
            <span className="px-2 py-0.5 rounded bg-slate-800 border border-cyber-border">PNG / BMP / JPEG</span>
            <span className="px-2 py-0.5 rounded bg-slate-800 border border-cyber-border">WAV PCM</span>
            <span className="px-2 py-0.5 rounded bg-slate-800 border border-cyber-border">ZIP / Nested</span>
            <span className="px-2 py-0.5 rounded bg-slate-800 border border-cyber-border">PDF / Office</span>
            <span className="px-2 py-0.5 rounded bg-slate-800 border border-cyber-border">Text / Unicode</span>
          </div>
        </div>
      </div>

      {/* Selected File Pre-Flight Inspection */}
      {selectedFile && (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-cyber-border pb-3">
            <span className="text-sm font-bold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyber-cyan" />
              Pre-Flight Quarantine Diagnostics
            </span>
            <span className="text-cyber-green flex items-center gap-1">
              <CheckCircle2 className="w-4 h-4" /> Ready for Intake
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <span className="text-slate-400 block mb-1">File Name:</span>
              <span className="text-white font-semibold truncate block">{selectedFile.name}</span>
            </div>
            <div>
              <span className="text-slate-400 block mb-1">Size:</span>
              <span className="text-white">{(selectedFile.size / 1024).toFixed(2)} KB ({selectedFile.size} bytes)</span>
            </div>
            <div className="md:col-span-2">
              <span className="text-slate-400 block mb-1">Client SHA-256 Digest:</span>
              <span className="text-cyber-cyan break-all">
                {calculatingHash ? "Calculating digest..." : fileSha256}
              </span>
            </div>
          </div>

          {/* Configurable Candidate Budget */}
          <div className="pt-3 border-t border-cyber-border">
            <label className="block text-slate-300 mb-1 font-bold">
              Candidate Hypotheses Search Budget:
            </label>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min="20"
                max="500"
                step="20"
                value={maxCandidates}
                onChange={(e) => setMaxCandidates(Number(e.target.value))}
                className="w-full accent-cyber-cyan"
              />
              <span className="text-cyber-cyan font-bold w-12 text-right">
                {maxCandidates}
              </span>
            </div>
            <p className="text-[10px] text-slate-500 mt-1">
              Higher budgets test more channel permutations and bit planes (capped at 1000).
            </p>
          </div>

          <button
            onClick={handleUploadSubmit}
            disabled={uploading}
            className="w-full py-3 bg-cyber-cyan hover:bg-cyan-400 text-slate-950 font-bold font-mono text-sm rounded-lg transition-all glow-cyan flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {uploading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>ALLOCATING QUARANTINE & DISPATCHING JOB...</span>
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                <span>INITIATE FORENSIC ANALYSIS PIPELINE</span>
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
}
