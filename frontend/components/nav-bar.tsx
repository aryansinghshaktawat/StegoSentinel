"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Upload, LayoutDashboard, Settings as SettingsIcon } from "lucide-react";

export function NavBar() {
  const pathname = usePathname();

  const navItems = [
    { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    { name: "Analyze Artifact", href: "/upload", icon: Upload },
    { name: "Platform Settings", href: "/settings", icon: SettingsIcon },
  ];

  return (
    <nav className="border-b border-cyber-border bg-cyber-card/80 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center space-x-3">
            <Link href="/dashboard" className="flex items-center space-x-3 group">
              <div className="p-2 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan group-hover:bg-cyber-cyan/20 transition-all glow-cyan">
                <Shield className="w-6 h-6" />
              </div>
              <div>
                <span className="text-xl font-bold tracking-wider text-white font-mono flex items-center gap-2">
                  STEGO<span className="text-cyber-cyan">SENTINEL</span>
                </span>
                <span className="text-[10px] tracking-widest text-slate-400 font-mono block uppercase">
                  AI-Assisted DFIR Steganalysis
                </span>
              </div>
            </Link>
          </div>

          <div className="flex items-center space-x-1 sm:space-x-4">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-cyber-cyan/15 text-cyber-cyan border border-cyber-cyan/30"
                      : "text-slate-300 hover:text-white hover:bg-slate-800/50"
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.name}</span>
                </Link>
              );
            })}
          </div>

          <div className="hidden md:flex items-center space-x-3 border-l border-cyber-border pl-4">
            <div className="flex items-center space-x-2 bg-slate-900/60 px-3 py-1.5 rounded-full border border-cyber-border text-xs font-mono">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-green opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-green"></span>
              </span>
              <span className="text-slate-300">CORE ENGINE: ACTIVE</span>
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
