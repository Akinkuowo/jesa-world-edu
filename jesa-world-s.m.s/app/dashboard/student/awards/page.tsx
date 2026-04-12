"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, Trophy, Medal, Award, Sparkles, Star } from "lucide-react";

interface MedalData {
    subject: string;
    type: 'Gold' | 'Silver' | 'Bronze';
    rank: number;
    marks: number;
}

interface CertificateData {
    subject: string;
    title: string;
    marks: number;
}

interface AwardsData {
    term: string;
    medals: MedalData[];
    certificates: CertificateData[];
}

export default function StudentAwards() {
    const router = useRouter();
    const [awardsData, setAwardsData] = useState<AwardsData | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchAwards();
    }, []);

    const fetchAwards = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/student/awards`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                setAwardsData(await res.json());
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const getMedalColors = (type: string) => {
        switch(type) {
            case 'Gold': return 'from-yellow-300 to-amber-500 border-yellow-400 text-yellow-900 shadow-yellow-500/50';
            case 'Silver': return 'from-slate-200 to-slate-400 border-slate-300 text-slate-800 shadow-slate-400/50';
            case 'Bronze': return 'from-orange-300 to-orange-500 border-orange-400 text-amber-900 shadow-orange-500/50';
            default: return 'from-slate-100 to-slate-200 border-slate-200 text-slate-800 shadow-slate-200/50';
        }
    };

    return (
        <div className="min-h-screen bg-[#0f172a] text-white font-sans pb-20 overflow-hidden">
            {/* Header Banner */}
            <div className="bg-[#1e293b] h-64 w-full relative">
                {/* Decorative Elements */}
                <div className="absolute inset-0 bg-gradient-to-b from-[#1e293b] to-[#0f172a]" />
                <div className="absolute top-1/2 left-1/2 w-full h-[500px] -translate-x-1/2 -translate-y-1/2 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-amber-500/10 via-[#0f172a]/0 to-transparent blur-3xl pointer-events-none" />
                
                {/* Floating Stars */}
                <Star className="absolute top-10 left-1/4 w-4 h-4 text-amber-400/30 animate-pulse" />
                <Star className="absolute top-20 right-1/4 w-6 h-6 text-amber-400/40 animate-pulse delay-100" />
                <Star className="absolute bottom-10 left-1/3 w-3 h-3 text-amber-400/20 animate-pulse delay-300" />

                <div className="relative z-10 max-w-7xl mx-auto px-6 lg:px-10 h-full flex flex-col justify-center">
                    <button onClick={() => router.push('/dashboard/student')} className="absolute top-8 left-6 lg:left-10 p-2.5 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl transition-all flex items-center space-x-2 text-sm font-bold backdrop-blur-sm border border-white/10">
                        <ArrowLeft className="w-4 h-4" />
                        <span>Back to Dashboard</span>
                    </button>
                    <div className="mt-8 flex flex-col items-center text-center">
                        <div className="w-20 h-20 bg-gradient-to-br from-amber-300 to-amber-600 rounded-full p-1 shadow-2xl flex items-center justify-center text-white mb-6 animate-bounce shadow-amber-500/20 relative">
                            <Sparkles className="absolute -top-2 -right-2 w-6 h-6 text-amber-300 animate-pulse" />
                            <Trophy className="w-10 h-10" />
                        </div>
                        <h1 className="text-3xl lg:text-5xl font-black tracking-tight mb-2 bg-gradient-to-r from-amber-200 via-amber-400 to-amber-200 bg-clip-text text-transparent">Trophy Room</h1>
                        <p className="font-medium text-sm lg:text-base text-slate-400 uppercase tracking-[0.2em]">{awardsData?.term || "Academic Session"} Honors</p>
                    </div>
                </div>
            </div>

            <div className="max-w-7xl mx-auto px-6 lg:px-10 mt-12 relative z-20">
                {loading ? (
                    <div className="flex justify-center flex-col items-center py-20 text-amber-500/50">
                        <div className="w-10 h-10 border-4 border-amber-500/20 border-t-amber-500 rounded-full animate-spin mb-4" />
                        <p className="font-bold text-sm uppercase tracking-widest text-slate-400">Loading Honors...</p>
                    </div>
                ) : awardsData ? (
                    <div className="space-y-16">
                        
                        {/* Medals Section */}
                        <section>
                            <h2 className="flex items-center gap-3 text-2xl font-black tracking-widest uppercase text-slate-200 mb-8 border-b border-slate-800 pb-4">
                                <Medal className="w-6 h-6 text-amber-400 relative -top-0.5" /> Subject Rankings
                            </h2>
                            {awardsData.medals.length > 0 ? (
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                                    {awardsData.medals.map((medal, index) => (
                                        <div key={index} className="group relative">
                                            {/* Glow Effect */}
                                            <div className={`absolute -inset-0.5 bg-gradient-to-br ${getMedalColors(medal.type)} rounded-[2.5rem] blur opacity-20 group-hover:opacity-40 transition duration-500`} />
                                            
                                            <div className="relative h-full bg-[#1e293b] rounded-[2.5rem] p-8 border border-slate-700/50 hover:border-slate-600 transition-colors flex flex-col items-center text-center">
                                                <div className={`w-24 h-24 rounded-full bg-gradient-to-br ${getMedalColors(medal.type)} flex items-center justify-center p-1.5 mb-6 shadow-2xl`}>
                                                    <div className="w-full h-full rounded-full border border-white/20 bg-black/10 flex items-center justify-center">
                                                        <span className="text-3xl font-black">{medal.rank}{medal.rank===1?'st':medal.rank===2?'nd':'rd'}</span>
                                                    </div>
                                                </div>
                                                <h3 className="text-xl font-black mb-2 text-slate-200">{medal.subject}</h3>
                                                <p className="text-xs uppercase tracking-widest font-bold text-slate-400 mb-6">{medal.type} Medal</p>
                                                
                                                <div className="mt-auto px-6 py-2 bg-slate-800/50 rounded-full border border-slate-700">
                                                    <span className="text-sm font-bold text-slate-300">Score: <span className="text-white">{medal.marks}%</span></span>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="py-12 flex flex-col items-center justify-center bg-[#1e293b]/50 rounded-[2rem] border border-slate-800 border-dashed">
                                    <Medal className="w-12 h-12 text-slate-600 mb-4" />
                                    <h3 className="text-lg font-bold text-slate-400 mb-1">No medals earned yet.</h3>
                                    <p className="text-xs text-slate-500 font-medium tracking-wide uppercase">Keep pushing for top 3!</p>
                                </div>
                            )}
                        </section>

                        {/* Certificates Section */}
                        <section>
                            <h2 className="flex items-center gap-3 text-2xl font-black tracking-widest uppercase text-slate-200 mb-8 border-b border-slate-800 pb-4">
                                <Award className="w-6 h-6 text-emerald-400 relative -top-0.5" /> Excellence Certificates
                            </h2>
                            {awardsData.certificates.length > 0 ? (
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                    {awardsData.certificates.map((cert, index) => (
                                        <div key={index} className="bg-gradient-to-br from-[#1e293b] to-slate-900 rounded-3xl p-8 border border-emerald-500/20 hover:border-emerald-500/40 transition-colors shadow-xl shadow-emerald-900/10 relative overflow-hidden flex flex-col">
                                            <div className="absolute -right-10 -top-10 w-40 h-40 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
                                            
                                            <h4 className="text-[10px] font-black uppercase tracking-[0.2em] text-emerald-400 mb-6">Subject Excellence</h4>
                                            
                                            <h3 className="text-2xl font-black text-slate-100 mb-2">{cert.subject}</h3>
                                            <p className="text-sm font-bold text-emerald-300/80 mb-6 font-serif italic">"{cert.title}"</p>
                                            
                                            <div className="mt-auto flex items-center justify-between pt-6 border-t border-slate-800">
                                                <div className="flex items-center gap-2 text-slate-400">
                                                    <Award className="w-4 h-4" />
                                                    <span className="text-xs font-bold uppercase tracking-widest">Achieved</span>
                                                </div>
                                                <span className="text-xl font-black text-emerald-400">{cert.marks}<span className="text-sm text-emerald-600 ml-0.5">%</span></span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="py-12 flex flex-col items-center justify-center bg-[#1e293b]/50 rounded-[2rem] border border-slate-800 border-dashed">
                                    <Award className="w-12 h-12 text-slate-600 mb-4" />
                                    <h3 className="text-lg font-bold text-slate-400 mb-1">No certificates awarded.</h3>
                                    <p className="text-xs text-slate-500 font-medium tracking-wide uppercase">Score 80% or above to earn one!</p>
                                </div>
                            )}
                        </section>

                    </div>
                ) : null}
            </div>
        </div>
    );
}
