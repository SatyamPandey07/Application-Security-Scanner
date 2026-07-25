import React from 'react';
import { ShieldCheck, Cpu, Database, Server } from 'lucide-react';

export default function App() {
  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex flex-col">
      <header className="border-b border-slate-800 bg-slate-950/50 backdrop-blur px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-8 h-8 text-emerald-400" />
          <h1 className="text-xl font-bold tracking-tight text-white">Sentinel</h1>
          <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            v0.1.0 Scaffold
          </span>
        </div>
      </header>

      <main className="flex-1 max-w-5xl mx-auto w-full p-8 flex flex-col justify-center items-center text-center">
        <div className="inline-flex items-center justify-center p-4 bg-emerald-500/10 text-emerald-400 rounded-full mb-6 ring-1 ring-emerald-500/20">
          <ShieldCheck className="w-12 h-12" />
        </div>
        <h2 className="text-3xl font-extrabold tracking-tight sm:text-4xl text-white mb-4">
          AI-Native Application Security Platform
        </h2>
        <p className="text-slate-400 max-w-2xl mb-12 text-lg">
          Repository scaffold complete. Sentinel core services, task queues, and interfaces are initialised and ready for feature modules.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-3xl">
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/40 text-left">
            <Server className="w-6 h-6 text-indigo-400 mb-3" />
            <h3 className="font-semibold text-white mb-1">FastAPI Backend</h3>
            <p className="text-xs text-slate-400">High-performance async API service serving endpoints & status.</p>
          </div>
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/40 text-left">
            <Database className="w-6 h-6 text-cyan-400 mb-3" />
            <h3 className="font-semibold text-white mb-1">PostgreSQL & Redis</h3>
            <p className="text-xs text-slate-400">Relational data persistence and job queue message brokering.</p>
          </div>
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/40 text-left">
            <Cpu className="w-6 h-6 text-emerald-400 mb-3" />
            <h3 className="font-semibold text-white mb-1">React + Tailwind</h3>
            <p className="text-xs text-slate-400">Modern responsive UI shell ready for findings dashboard.</p>
          </div>
        </div>
      </main>

      <footer className="border-t border-slate-800 py-4 px-6 text-center text-xs text-slate-500">
        Sentinel Platform &copy; 2026
      </footer>
    </div>
  );
}
