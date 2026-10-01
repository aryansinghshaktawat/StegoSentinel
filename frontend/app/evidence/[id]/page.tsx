"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import {
  GitBranch,
  Download,
  ArrowLeft,
  RefreshCw,
  Copy,
  Check,
  FileCode,
  FileText,
} from "lucide-react";
import { api } from "@/lib/api";
import { EvidenceObject } from "@/types";

export default function EvidenceTreePage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const resolvedParams = use(params);
  const analysisId = resolvedParams.id;

  const [tree, setTree] = useState<EvidenceObject[]>([]);
  const [loading, setLoading] = useState(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    const loadTree = async () => {
      try {
        const data = await api.getEvidenceTree(analysisId);
        setTree(data);
      } catch (e) {
        console.error("Error loading evidence tree:", e);
      } finally {
        setLoading(false);
      }
    };
    loadTree();
  }, [analysisId]);

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const renderNode = (node: EvidenceObject, depth: number = 0) => {
    return (
      <div key={node.id} className="relative space-y-3">
        <div
          className={`p-5 rounded-xl border transition-all ${
            depth === 0
              ? "bg-cyber-card border-cyber-cyan/50 glow-cyan"
              : "bg-slate-900/90 border-cyber-border ml-4 sm:ml-8"
          }`}
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyber-border/60 pb-3">
            <div className="flex items-center gap-2">
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                  depth === 0
                    ? "bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/30"
                    : "bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30"
                }`}
              >
                DEPTH {node.recursion_depth}
              </span>
              <h3 className="font-mono font-bold text-white text-base flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyber-cyan" />
                {node.name}
              </h3>
            </div>

            <div className="flex items-center gap-2">
              {node.decode_status && (
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    node.decode_status === "SUCCESS"
                      ? "bg-cyber-green/20 text-cyber-green border border-cyber-green/40"
                      : node.decode_status === "IDENTIFIED"
                      ? "bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40"
                      : "bg-slate-800 text-slate-400"
                  }`}
                >
                  DECODE: {node.decode_status}
                </span>
              )}
              <a
                href={api.getDownloadUrl(node.id)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyber-cyan text-xs font-mono font-bold border border-cyber-border"
              >
                <Download className="w-3.5 h-3.5" />
                <span>EXPORT PAYLOAD</span>
              </a>
            </div>
          </div>

          {/* Complete Forensic Properties (Requirement 20) */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs pt-3">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Extraction Method</span>
              <span className="text-white font-semibold">{node.extraction_method}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Identified Format</span>
              <span className="text-cyber-cyan font-bold">{node.detected_type}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Payload Size</span>
              <span className="text-white">{node.size} bytes</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Source Offset</span>
              <span className="text-white font-mono">0x{node.source_offset.toString(16).toUpperCase()}</span>
            </div>

            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Parent Artifact</span>
              <span className="text-slate-300 truncate block text-[11px] font-mono">
                {node.parent_id || "Root Artifact (depth 0)"}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Decode Status</span>
              <span className="text-white font-bold">{node.decode_status || "N/A"}</span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-slate-500 block text-[10px] uppercase">Candidate ID</span>
              <span className="text-slate-300 truncate block text-[11px] font-mono">
                {node.candidate_id || "N/A (Archive/Overlay node)"}
              </span>
            </div>

            <div className="col-span-2 sm:col-span-4">
              <span className="text-slate-500 block text-[10px] uppercase">Cryptographic SHA-256 Digest:</span>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-cyber-cyan break-all bg-black/50 px-2 py-1 rounded border border-slate-800 flex-1 font-mono text-[11px]">
                  {node.sha256}
                </span>
                <button
                  onClick={() => copyText(node.sha256, node.id + "_sha")}
                  className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                  title="Copy SHA-256"
                >
                  {copiedId === node.id + "_sha" ? (
                    <Check className="w-3.5 h-3.5 text-cyber-green" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Decoded Text Visible in DAG (Requirement 20) */}
          {node.decoded_text && (
            <div className="mt-4 pt-3 border-t border-cyber-border/80 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-cyber-green flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5" />
                  RECOVERED DECODED TEXT
                </span>
                <button
                  onClick={() => copyText(node.decoded_text!, node.id + "_txt")}
                  className="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono text-cyber-cyan hover:bg-slate-800 border border-cyber-border"
                >
                  {copiedId === node.id + "_txt" ? (
                    <>
                      <Check className="w-3 h-3 text-cyber-green" />
                      <span>COPIED</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>COPY TEXT</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="bg-black/60 border border-cyber-green/30 rounded p-3 text-cyber-green text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">
                {node.decoded_text}
              </pre>
            </div>
          )}
        </div>

        {/* Recursive Children (Tree structure) */}
        {node.children && node.children.length > 0 && (
          <div className="space-y-3 pl-4 border-l-2 border-cyber-cyan/40 ml-4 sm:ml-6">
            {node.children.map((child) => renderNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-8">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border pb-6">
        <div>
          <Link
            href={`/analysis/${analysisId}`}
            className="inline-flex items-center gap-1 text-xs font-mono text-cyber-cyan hover:underline mb-2"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Return to Case Analysis
          </Link>
          <h1 className="text-3xl font-extrabold font-mono text-white tracking-tight flex items-center gap-3">
            <GitBranch className="w-7 h-7 text-cyber-cyan" />
            RECURSIVE EVIDENCE <span className="text-cyber-cyan">HIERARCHY</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Visual Directed Acyclic Graph (DAG) of parent artifacts and recursively extracted child payloads.
          </p>
        </div>
      </div>

      {loading ? (
        <div className="py-24 text-center font-mono space-y-4">
          <RefreshCw className="w-8 h-8 animate-spin mx-auto text-cyber-cyan" />
          <p className="text-sm text-slate-400">Loading evidence DAG...</p>
        </div>
      ) : tree.length === 0 ? (
        <div className="py-20 text-center font-mono space-y-3 bg-cyber-card border border-cyber-border rounded-xl p-8">
          <p className="text-slate-400 text-sm">No evidence objects recorded for this case.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {tree.map((rootNode) => renderNode(rootNode, 0))}
        </div>
      )}
    </div>
  );
}

