"use client";

import { useState, useEffect } from "react";
import toast from "react-hot-toast";
import { 
    Calendar, 
    Shield, 
    Save, 
    Loader2, 
    AlertCircle,
    Info,
    CheckCircle2
} from "lucide-react";

export default function AcademicSession() {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [form, setForm] = useState({
        currentTerm: "1st Term",
        sessionStartYear: "",
        sessionEndYear: ""
    });

    const fetchSessionData = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/school`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setForm({
                    currentTerm: data.currentTerm || "1st Term",
                    sessionStartYear: data.sessionStartYear?.toString() || "",
                    sessionEndYear: data.sessionEndYear?.toString() || ""
                });
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchSessionData();
    }, []);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        try {
            const token = localStorage.getItem("token");
            // We use the same school endpoint but only send session data
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/school`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    currentTerm: form.currentTerm,
                    sessionStartYear: form.sessionStartYear,
                    sessionEndYear: form.sessionEndYear,
                    currentSession: `${form.sessionStartYear}/${form.sessionEndYear}`
                })
            });

            if (res.ok) {
                toast.success("Academic session updated successfully!");
                // Trigger an event so the parent dashboard can refresh its badge if needed
                window.dispatchEvent(new Event('sessionUpdate'));
            } else {
                toast.error("Failed to update session");
            }
        } catch (err) {
            toast.error("Network error");
        } finally {
            setSaving(false);
        }
    };

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center p-20 text-slate-400">
                <Loader2 className="w-10 h-10 animate-spin mb-4 text-indigo-600" />
                <p className="font-black uppercase tracking-widest text-xs">Loading Session Info...</p>
            </div>
        );
    }

    return (
        <div className="max-w-4xl space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {/* Context Widget */}
            <div className="bg-indigo-600 rounded-[2.5rem] p-10 text-white shadow-2xl shadow-indigo-600/30 relative overflow-hidden group">
                <div className="absolute -right-10 -top-10 w-64 h-64 bg-white/10 rounded-full group-hover:scale-110 transition-transform duration-1000" />
                <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-8">
                    <div className="space-y-4">
                        <div className="flex items-center gap-3">
                            <div className="p-3 bg-white/10 rounded-2xl backdrop-blur-md">
                                <Calendar className="w-8 h-8 text-white" />
                            </div>
                            <div>
                                <h2 className="text-3xl font-black tracking-tight">Academic Timeline</h2>
                                <p className="text-indigo-100 font-medium opacity-80">Manage your school's current year and active term.</p>
                            </div>
                        </div>
                    </div>
                    <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-3xl p-6 px-10">
                        <div className="text-[10px] font-black uppercase tracking-[0.2em] text-indigo-200 mb-1">Active Now</div>
                        <div className="text-2xl font-black">{form.sessionStartYear}/{form.sessionEndYear} • {form.currentTerm}</div>
                    </div>
                </div>
            </div>

            <div className="grid lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2">
                    <form onSubmit={handleSubmit} className="bg-white rounded-[2.5rem] border border-slate-200 p-10 shadow-xl shadow-slate-200/50 space-y-8">
                        <div className="space-y-8">
                            <div>
                                <h3 className="text-sm font-black text-slate-400 uppercase tracking-[0.2em] mb-6 flex items-center gap-2">
                                    <Info className="w-4 h-4 text-indigo-500" />
                                    Session Configuration
                                </h3>
                                <div className="grid md:grid-cols-2 gap-6">
                                    <div className="space-y-3">
                                        <label className="text-xs font-black text-slate-700 uppercase tracking-widest ml-1">Start Year</label>
                                        <input
                                            required
                                            type="number"
                                            placeholder="e.g. 2023"
                                            value={form.sessionStartYear}
                                            onChange={e => setForm({ ...form, sessionStartYear: e.target.value })}
                                            className="w-full bg-slate-50 border-2 border-slate-100 rounded-2xl p-4 text-sm font-bold focus:outline-none focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all"
                                        />
                                    </div>
                                    <div className="space-y-3">
                                        <label className="text-xs font-black text-slate-700 uppercase tracking-widest ml-1">End Year</label>
                                        <input
                                            required
                                            type="number"
                                            placeholder="e.g. 2024"
                                            value={form.sessionEndYear}
                                            onChange={e => setForm({ ...form, sessionEndYear: e.target.value })}
                                            className="w-full bg-slate-50 border-2 border-slate-100 rounded-2xl p-4 text-sm font-bold focus:outline-none focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all"
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="pt-8 border-t border-slate-100">
                                <h3 className="text-sm font-black text-slate-400 uppercase tracking-[0.2em] mb-6 flex items-center gap-2">
                                    <Shield className="w-4 h-4 text-indigo-500" />
                                    Active Term selection
                                </h3>
                                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                    {['1st Term', '2nd Term', '3rd Term'].map((term) => (
                                        <button
                                            key={term}
                                            type="button"
                                            onClick={() => setForm({ ...form, currentTerm: term })}
                                            className={`p-6 rounded-3xl border-2 transition-all flex flex-col items-center gap-3 group relative overflow-hidden ${
                                                form.currentTerm === term 
                                                ? 'bg-indigo-600 border-indigo-600 text-white shadow-xl shadow-indigo-600/20' 
                                                : 'bg-white border-slate-100 text-slate-600 hover:border-indigo-300'
                                            }`}
                                        >
                                            {form.currentTerm === term && (
                                                <div className="absolute top-2 right-2">
                                                    <CheckCircle2 className="w-5 h-5 text-white/50" />
                                                </div>
                                            )}
                                            <span className={`text-xs font-black uppercase tracking-widest ${form.currentTerm === term ? 'text-indigo-200' : 'text-slate-400 group-hover:text-indigo-400'}`}>Session Phase</span>
                                            <span className="text-lg font-black">{term}</span>
                                        </button>
                                    ))}
                                </div>
                                <p className="mt-6 text-[11px] text-slate-400 font-bold italic flex items-center gap-2">
                                    <AlertCircle className="w-4 h-4 text-amber-500" />
                                    Updating the term affects real-time GPA calculations across the school.
                                </p>
                            </div>
                        </div>

                        <button
                            type="submit"
                            disabled={saving}
                            className="w-full flex items-center justify-center space-x-3 bg-slate-900 text-white py-5 px-8 rounded-[1.5rem] font-black hover:bg-slate-800 transition-all shadow-2xl shadow-slate-900/40 disabled:opacity-70 group"
                        >
                            {saving ? <Loader2 className="w-6 h-6 animate-spin" /> : <Save className="w-6 h-6 group-hover:scale-110 transition-transform" />}
                            <span className="uppercase tracking-[0.2em] text-xs">Finalize Session Update</span>
                        </button>
                    </form>
                </div>

                <div className="space-y-6">
                    <div className="bg-slate-50 rounded-[2.5rem] p-8 border border-slate-200">
                        <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] mb-4">Why this matters</h4>
                        <div className="space-y-6">
                            <div className="flex gap-4">
                                <div className="w-8 h-8 bg-white rounded-lg border border-slate-200 flex items-center justify-center flex-shrink-0">
                                    <span className="text-xs font-black text-indigo-600">01</span>
                                </div>
                                <p className="text-xs font-bold text-slate-600 leading-relaxed">The active session determines which students are eligible for promotion or graduation.</p>
                            </div>
                            <div className="flex gap-4">
                                <div className="w-8 h-8 bg-white rounded-lg border border-slate-200 flex items-center justify-center flex-shrink-0">
                                    <span className="text-xs font-black text-indigo-600">02</span>
                                </div>
                                <p className="text-xs font-bold text-slate-600 leading-relaxed">Attendance records are strictly isolated by session and term to ensure accurate reporting.</p>
                            </div>
                        </div>
                    </div>

                    <div className="bg-amber-50 rounded-[2.5rem] p-8 border border-amber-100 flex flex-col items-center text-center">
                        <div className="w-12 h-12 bg-white rounded-full flex items-center justify-center shadow-lg shadow-amber-900/10 mb-4">
                            <AlertCircle className="w-6 h-6 text-amber-600" />
                        </div>
                        <h4 className="text-xs font-black text-amber-900 uppercase tracking-widest mb-2">Year Transition</h4>
                        <p className="text-[10px] font-bold text-amber-700/80">Changing the year values will reset the curriculum schedule for current teachers. Proceed with caution.</p>
                    </div>
                </div>
            </div>
        </div>
    );
}
