"use client";

import { useEffect, useState } from "react";
import { Settings, Shield, HardDrive, Terminal, CheckCircle2, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import { HealthStatus } from "@/types";

export default function SettingsPage() {
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    api.getHealth().then(setHealth).catch(console.error);
  }, []);

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div className="border-b border-cyber-border pb-6">
        <h1 className="text-3xl font-extrabold font-mono text-white tracking-tight flex items-center gap-3">
          <Settings className="w-7 h-7 text-cyber-cyan" />
          PLATFORM CONFIGURATION <span className="text-cyber-cyan">& LIMITS</span>
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Review system hard budgets, storage isolation, and external tool integration adapters.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
        {/* Hard Resource Budgets */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-cyber-border pb-3">
            <Shield className="w-4 h-4 text-cyber-cyan" />
            <h2 className="text-sm font-bold text-white uppercase">
              Forensic Guardrail Budgets
            </h2>
          </div>

          <div className="space-y-3">
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">MAX_UPLOAD_SIZE:</span>
              <span className="text-white font-bold">100 MB</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">MAX_TOTAL_EXTRACTED_SIZE:</span>
              <span className="text-white font-bold">250 MB</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">MAX_RECURSION_DEPTH:</span>
              <span className="text-cyber-cyan font-bold">3 Levels</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">MAX_EXTRACTED_OBJECTS:</span>
              <span className="text-white font-bold">20 Artifacts</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">MAX_CANDIDATES:</span>
              <span className="text-white font-bold">1000 Hypotheses</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">DECOMPRESSION_BOMB_RATIO:</span>
              <span className="text-cyber-red font-bold">100:1 (Enforced)</span>
            </div>
          </div>
        </div>

        {/* Runtime Environment & Storage */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-cyber-border pb-3">
            <HardDrive className="w-4 h-4 text-cyber-cyan" />
            <h2 className="text-sm font-bold text-white uppercase">
              Storage & Isolation Architecture
            </h2>
          </div>

          <div className="space-y-3">
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">Quarantine Storage:</span>
              <span className="text-cyber-green font-bold">LOCAL (0600 RESTRICTED)</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">Database Engine:</span>
              <span className="text-cyber-green font-bold">
                {health?.checks?.database?.status === "UP" ? "SQLAlchemy Unified" : "OFFLINE"}
              </span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">Worker Sandboxing:</span>
              <span className="text-cyber-cyan font-bold">Least-Privilege Non-Root</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">Payload Execution Policy:</span>
              <span className="text-cyber-red font-bold">STRICTLY PROHIBITED</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-cyber-border">
              <span className="text-slate-400">LLM Explanation Layer:</span>
              <span className="text-cyber-cyan font-bold">MOCK (DETERMINISTIC)</span>
            </div>
          </div>
        </div>

        {/* External Tool Adapters Status */}
        <div className="md:col-span-2 bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-cyber-border pb-3">
            <Terminal className="w-4 h-4 text-cyber-cyan" />
            <h2 className="text-sm font-bold text-white uppercase">
              External Forensic Tool Capabilities
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {health?.checks?.external_tools &&
              Object.entries(health.checks.external_tools).map(([tool, ready]) => (
                <div
                  key={tool}
                  className="p-4 rounded-lg bg-slate-900/60 border border-cyber-border flex items-center justify-between"
                >
                  <div>
                    <span className="font-bold text-white block capitalize">{tool}</span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">
                      {ready ? "Native binary detected" : "Native fallback active"}
                    </span>
                  </div>
                  {ready ? (
                    <CheckCircle2 className="w-5 h-5 text-cyber-green" />
                  ) : (
                    <XCircle className="w-5 h-5 text-slate-500" />
                  )}
                </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
}
