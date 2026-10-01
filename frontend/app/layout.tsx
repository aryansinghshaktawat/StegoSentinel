import type { Metadata } from "next";
import "./globals.css";
import { NavBar } from "@/components/nav-bar";

export const metadata: Metadata = {
  title: "StegoSentinel | AI-Assisted Steganalysis & Hidden-Payload Forensics",
  description: "Enterprise defensible DFIR platform for multi-format steganalysis, candidate ranking, and safe payload extraction.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-cyber-dark text-slate-100 min-h-screen flex flex-col antialiased selection:bg-cyber-cyan/30 selection:text-white">
        <NavBar />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>
        <footer className="border-t border-cyber-border py-4 text-center text-xs text-slate-500 font-mono">
          StegoSentinel v0.1.0 • Defensible Digital Forensics & Incident Response Platform • Zero Payload Execution Policy
        </footer>
      </body>
    </html>
  );
}
