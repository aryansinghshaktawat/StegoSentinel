"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  FileSearch,
  Layers,
  ArrowUpRight,
  RefreshCw,
  Plus,
  Cpu,
  Clock,
} from "lucide-react";
import { api } from "@/lib/api";
import { AnalysisSummary, HealthStatus } from "@/types";

export default function DashboardPage() {
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const loadData = async () => {
    try {
      setRefreshing(true);
      const [analysesData, healthData] = await Promise.allSettled([
        api.getAnalyses(),
        api.getHealth(),
      ]);

      if (analysesData.status === "fulfilled") {
        setAnalyses(analysesData.value);
      }
      if (healthData.status === "fulfilled") {
        setHealth(healthData.value);
      }
    } catch (e) {
      console.error("Dashboard data load error:", e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const totalCases = analyses.length;
  const suspectedCases = analyses.filter(
    (a) => (a.stego_likelihood || 0) >= 0.7
  ).length;
  const lowRiskCases = analyses.filter(
    (a) => (a.stego_likelihood || 0) < 0.4 && a.status === "COMPLETED"
  ).length;
  const processingCount = analyses.filter(
    (a) => a.status === "PENDING" || a.status === "RUNNING"
  ).length;

  return (
    <div className="space-y-8">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-cyber-border pb-6">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white font-mono">
            FORENSIC <span className="text-cyber-cyan">COMMAND DASHBOARD</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time digital forensics telemetry, covert payload detection, and recursive evidence intake.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={refreshing}
            className="flex items-center gap-2 px-3 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-sm font-mono rounded-lg border border-cyber-border transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`} />
            <span>SYNC</span>
          </button>
          <Link
            href="/upload"
            className="flex items-center gap-2 px-4 py-2 bg-cyber-cyan hover:bg-cyan-400 text-slate-950 text-sm font-semibold rounded-lg font-mono transition-all glow-cyan"
          >
            <Plus className="w-4 h-4" />
            <span>SUBMIT ARTIFACT</span>
          </Link>
        </div>
      </div>

      {/* KPI Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              Total Forensic Cases
            </span>
            <div className="p-2 rounded-lg bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/20">
              <Layers className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-mono font-bold text-white">
              {loading ? "..." : totalCases}
            </div>
            <p className="text-xs text-slate-400 mt-1">Quarantined artifacts triaged</p>
          </div>
        </div>

        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-cyber-red uppercase tracking-wider">
              Stego Likelihood ≥ 70%
            </span>
            <div className="p-2 rounded-lg bg-cyber-red/10 text-cyber-red border border-cyber-red/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-mono font-bold text-cyber-red">
              {loading ? "..." : suspectedCases}
            </div>
            <p className="text-xs text-slate-400 mt-1">High-confidence steganographic indicators</p>
          </div>
        </div>

        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-cyber-green uppercase tracking-wider">
              No Anomaly Observed
            </span>
            <div className="p-2 rounded-lg bg-cyber-green/10 text-cyber-green border border-cyber-green/20">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-mono font-bold text-cyber-green">
              {loading ? "..." : lowRiskCases}
            </div>
            <p className="text-xs text-slate-400 mt-1">Within standard statistical variance</p>
          </div>
        </div>

        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-cyber-amber uppercase tracking-wider">
              Active Queue Depth
            </span>
            <div className="p-2 rounded-lg bg-cyber-amber/10 text-cyber-amber border border-cyber-amber/20">
              <Clock className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-mono font-bold text-cyber-amber">
              {loading ? "..." : processingCount}
            </div>
            <p className="text-xs text-slate-400 mt-1">Running worker analysis tasks</p>
          </div>
        </div>
      </div>

      {/* Main Content Grid: Recent Cases & Diagnostic Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Cases Table */}
        <div className="lg:col-span-2 bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
          <div className="p-5 border-b border-cyber-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileSearch className="w-5 h-5 text-cyber-cyan" />
              <h2 className="text-base font-bold font-mono text-white">
                RECENT ANALYSES
              </h2>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Auto-refreshed every 10s
            </span>
          </div>

          <div className="overflow-x-auto">
            {loading ? (
              <div className="py-16 text-center text-slate-500 font-mono text-sm">
                Loading telemetry logs...
              </div>
            ) : analyses.length === 0 ? (
              <div className="py-16 text-center text-slate-500 font-mono text-sm space-y-3">
                <p>No forensic cases registered yet.</p>
                <Link
                  href="/upload"
                  className="inline-flex items-center gap-1.5 text-cyber-cyan hover:underline text-xs"
                >
                  <Plus className="w-3.5 h-3.5" /> Submit your first artifact
                </Link>
              </div>
            ) : (
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-900/80 text-xs font-mono text-slate-400 uppercase border-b border-cyber-border">
                  <tr>
                    <th className="py-3 px-4">Artifact</th>
                    <th className="py-3 px-4">SHA-256</th>
                    <th className="py-3 px-4">Format</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Likelihood</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border font-mono text-xs">
                  {analyses.map((item) => {
                    const likelihood = item.stego_likelihood !== null && item.stego_likelihood !== undefined
                      ? Math.round(item.stego_likelihood * 100)
                      : null;

                    return (
                      <tr
                        key={item.id}
                        className="hover:bg-slate-800/40 transition-colors"
                      >
                        <td className="py-3 px-4 font-semibold text-white">
                          <Link
                            href={`/analysis/${item.id}`}
                            className="hover:text-cyber-cyan flex items-center gap-1.5"
                          >
                            {item.original_filename}
                          </Link>
                        </td>
                        <td className="py-3 px-4 text-slate-400 font-mono">
                          {item.sha256.substring(0, 10)}...
                        </td>
                        <td className="py-3 px-4 text-slate-300">
                          {item.detected_type.split("/")[1] || item.detected_type}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              item.status === "COMPLETED"
                                ? "bg-cyber-green/15 text-cyber-green border border-cyber-green/30"
                                : item.status === "RUNNING"
                                ? "bg-cyber-blue/15 text-cyber-blue border border-cyber-blue/30 animate-pulse"
                                : item.status === "FAILED"
                                ? "bg-cyber-red/15 text-cyber-red border border-cyber-red/30"
                                : "bg-slate-800 text-slate-300"
                            }`}
                          >
                            {item.status}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          {likelihood !== null ? (
                            <div className="flex items-center gap-2">
                              <div className="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                <div
                                  className={`h-full ${
                                    likelihood >= 70
                                      ? "bg-cyber-red"
                                      : likelihood >= 40
                                      ? "bg-cyber-amber"
                                      : "bg-cyber-green"
                                  }`}
                                  style={{ width: `${likelihood}%` }}
                                ></div>
                              </div>
                              <span
                                className={
                                  likelihood >= 70
                                    ? "text-cyber-red font-bold"
                                    : likelihood >= 40
                                    ? "text-cyber-amber"
                                    : "text-cyber-green"
                                }
                              >
                                {likelihood}%
                              </span>
                            </div>
                          ) : (
                            <span className="text-slate-500">—</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <Link
                            href={`/analysis/${item.id}`}
                            className="inline-flex items-center gap-1 text-cyber-cyan hover:underline"
                          >
                            <span>Inspect</span>
                            <ArrowUpRight className="w-3.5 h-3.5" />
                          </Link>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* System Diagnostics & Capabilities */}
        <div className="space-y-6">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-5">
            <div className="flex items-center gap-2 border-b border-cyber-border pb-3 mb-4">
              <Cpu className="w-5 h-5 text-cyber-cyan" />
              <h2 className="text-base font-bold font-mono text-white">
                ENGINE DIAGNOSTICS
              </h2>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
                <span className="text-slate-400">Database Backend:</span>
                <span className="text-cyber-green font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-green"></span>
                  {health?.checks?.database?.status || "ONLINE"}
                </span>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
                <span className="text-slate-400">Quarantine Storage:</span>
                <span className="text-cyber-green font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-green"></span>
                  {health?.checks?.quarantine_storage?.status || "ISOLATED"}
                </span>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
                <span className="text-slate-400">Async Task Broker:</span>
                <span className="text-cyber-cyan font-bold">
                  {health?.checks?.redis?.mode === "thread"
                    ? "IN-PROCESS (DEV)"
                    : "REDIS QUEUE"}
                </span>
              </div>
            </div>

            <div className="mt-5 pt-4 border-t border-cyber-border">
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-2">
                External Forensic Adapters
              </h3>
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                {health?.checks?.external_tools &&
                  Object.entries(health.checks.external_tools).map(
                    ([tool, available]) => (
                      <div
                        key={tool}
                        className="flex items-center justify-between p-2 rounded bg-slate-900/40 border border-cyber-border/60"
                      >
                        <span className="text-slate-300">{tool}</span>
                        <span
                          className={`font-bold ${
                            available ? "text-cyber-green" : "text-slate-500"
                          }`}
                        >
                          {available ? "READY" : "FALLBACK"}
                        </span>
                      </div>
                    )
                  )}
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-br from-cyber-card to-slate-900 border border-cyber-border rounded-xl p-5">
            <h3 className="text-sm font-bold font-mono text-white mb-2">
              ZERO PAYLOAD EXECUTION DIRECTIVE
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Every uploaded artifact and extracted payload is quarantined as strictly untrusted.
              Binaries and scripts are never invoked directly by the forensic workflow.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
