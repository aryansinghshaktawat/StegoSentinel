"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import {
  GitBranch,
  Download,
  ArrowLeft,
  RefreshCw,
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

  const renderNode = (node: EvidenceObject, depth: number = 0) => {
    return (
      <div key={node.id} className="relative space-y-4">
        <div
          className={`p-5 rounded-xl border transition-all ${
            depth === 0
              ? "bg-cyber-card border-cyber-cyan/50 glow-cyan"
              : "bg-slate-900/80 border-cyber-border ml-6 sm:ml-10"
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
              <h3 className="font-mono font-bold text-white text-base">
                {node.name}
              </h3>
            </div>

            <a
              href={api.getDownloadUrl(node.id)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyber-cyan text-xs font-mono font-bold border border-cyber-border self-start sm:self-auto"
            >
              <Download className="w-3.5 h-3.5" />
              <span>EXPORT PAYLOAD</span>
            </a>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs pt-3">
            <div>
              <span className="text-slate-500 block text-[10px]">Extraction Method:</span>
              <span className="text-slate-300 font-semibold">{node.extraction_method}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Identified Format:</span>
              <span className="text-cyber-cyan">{node.detected_type}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Payload Size:</span>
              <span className="text-white">{node.size} bytes</span>
            </div>
            <div className="sm:col-span-3">
              <span className="text-slate-500 block text-[10px]">SHA-256 Digest:</span>
              <span className="text-slate-400 break-all bg-black/40 px-2 py-0.5 rounded border border-slate-800 inline-block mt-0.5">
                {node.sha256}
              </span>
            </div>
          </div>
        </div>

        {/* Recursive Children */}
        {node.children && node.children.length > 0 && (
          <div className="space-y-4 pl-4 border-l-2 border-cyber-cyan/30 ml-4 sm:ml-6">
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
