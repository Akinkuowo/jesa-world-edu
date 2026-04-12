"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, FileText, Download, TrendingUp, BookOpen, Clock } from "lucide-react";

interface ReportSubject {
    id: string;
    subject: string;
    testScore: number;
    examScore: number;
    totalMarks: number;
    grade: string;
    remark: string;
}

interface ReportData {
    term: string;
    subjects: ReportSubject[];
    totalMarks: number;
    average: number;
    gpa: number;
}

export default function StudentReports() {
    const router = useRouter();
    const [reportData, setReportData] = useState<ReportData | null>(null);
    const [loading, setLoading] = useState(true);
    const [selectedTerm, setSelectedTerm] = useState("First Term");

    useEffect(() => {
        fetchReportCard();
    }, [selectedTerm]);

    const fetchReportCard = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/student/reports?term=${selectedTerm}`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setReportData(data);
                // Also default the picker to whatever term was returned to ensure consistency
                if (data.term && data.term !== selectedTerm) {
                    setSelectedTerm(data.term);
                }
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const handlePrint = () => {
        window.print();
    };

    return (
        <div className="min-h-screen bg-[#f1f3f6] text-slate-900 font-sans pb-20 print:bg-white print:pb-0">
            {/* Header Banner - hidden when printing */}
            <div className="bg-indigo-700 h-48 lg:h-64 w-full relative overflow-hidden print:hidden">
                <div className="absolute inset-0 bg-gradient-to-r from-indigo-700 to-purple-700 opacity-90" />
                <div className="absolute -right-20 -top-20 w-80 h-80 bg-white/10 rounded-full blur-3xl" />
                <div className="absolute -left-20 -bottom-20 w-80 h-80 bg-white/10 rounded-full blur-3xl" />

                <div className="relative z-10 max-w-7xl mx-auto px-6 lg:px-10 h-full flex flex-col justify-center">
                    <button onClick={() => router.push('/dashboard/student')} className="absolute top-8 left-6 lg:left-10 p-2.5 bg-white/10 hover:bg-white/20 text-white rounded-xl transition-all flex items-center space-x-2 text-sm font-bold backdrop-blur-sm">
                        <ArrowLeft className="w-4 h-4" />
                        <span>Back to Dashboard</span>
                    </button>
                    <div className="mt-8 flex items-center space-x-4">
                        <div className="w-16 h-16 bg-white rounded-2xl p-1 shadow-2xl flex items-center justify-center text-indigo-600">
                            <FileText className="w-8 h-8" />
                        </div>
                        <div className="text-white flex-1">
                            <h1 className="text-3xl lg:text-4xl font-black tracking-tight mb-1">Academic Reports</h1>
                            <p className="opacity-80 font-medium text-sm lg:text-base">Review your detailed performance metrics and grades.</p>
                        </div>
                        <button onClick={handlePrint} className="px-6 py-3 bg-white text-indigo-600 font-black text-sm uppercase tracking-widest rounded-xl hover:bg-indigo-50 hover:scale-105 transition-all shadow-xl shadow-indigo-900/20 flex items-center gap-2">
                            <Download className="w-4 h-4" /> Download PDF
                        </button>
                    </div>
                </div>
            </div>

            <div className="max-w-7xl mx-auto px-6 lg:px-10 -mt-8 relative z-20 print:mt-0 print:px-0">
                <div className="bg-white rounded-[2rem] p-8 shadow-xl shadow-slate-200/60 border border-white min-h-[60vh] print:shadow-none print:border-none print:p-0">
                    
                    {/* Controls */}
                    <div className="flex items-center justify-between mb-8 print:hidden">
                        <div className="flex items-center gap-4">
                            <label className="text-xs font-black uppercase tracking-widest text-slate-400">Select Term</label>
                            <select 
                                value={selectedTerm}
                                onChange={(e) => setSelectedTerm(e.target.value)}
                                className="bg-slate-50 border-2 border-transparent focus:border-indigo-500/20 focus:bg-white rounded-xl px-6 py-3 outline-none transition-all font-bold text-slate-700 appearance-none cursor-pointer text-sm"
                            >
                                <option value="First Term">First Term</option>
                                <option value="Second Term">Second Term</option>
                                <option value="Third Term">Third Term</option>
                            </select>
                        </div>
                    </div>

                    {/* Print Header */}
                    <div className="hidden print:block text-center border-b-2 border-slate-900 pb-6 mb-8 mt-10">
                        <h1 className="text-3xl font-black uppercase tracking-widest mb-2">Student Report Card</h1>
                        <h2 className="text-lg font-bold text-slate-500 uppercase tracking-widest">{reportData?.term || selectedTerm}</h2>
                    </div>

                    {loading ? (
                        <div className="flex justify-center flex-col items-center py-20 text-indigo-300">
                            <div className="w-10 h-10 border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin mb-4" />
                            <p className="font-bold text-sm uppercase tracking-widest">Compiling Report...</p>
                        </div>
                    ) : reportData && reportData.subjects.length > 0 ? (
                        <div className="animate-in fade-in duration-500">
                            {/* Summary Cards */}
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                                <div className="bg-gradient-to-br from-indigo-50 to-purple-50 p-6 rounded-[2rem] border border-indigo-100/50 print:border-2 print:border-slate-200">
                                    <div className="flex items-center gap-3 text-indigo-600 mb-4">
                                        <div className="p-2 bg-indigo-100 rounded-xl"><TrendingUp className="w-5 h-5" /></div>
                                        <span className="text-xs font-black uppercase tracking-widest">GPA Score</span>
                                    </div>
                                    <div className="text-4xl font-black text-slate-900">{reportData.gpa.toFixed(2)}<span className="text-xl text-slate-400 font-bold ml-1">/4.0</span></div>
                                </div>
                                <div className="bg-gradient-to-br from-indigo-50 to-purple-50 p-6 rounded-[2rem] border border-indigo-100/50 print:border-2 print:border-slate-200">
                                    <div className="flex items-center gap-3 text-emerald-600 mb-4">
                                        <div className="p-2 bg-emerald-100 rounded-xl"><BookOpen className="w-5 h-5" /></div>
                                        <span className="text-xs font-black uppercase tracking-widest">Term Average</span>
                                    </div>
                                    <div className="text-4xl font-black text-slate-900">{reportData.average.toFixed(1)}<span className="text-xl text-slate-400 font-bold ml-1">%</span></div>
                                </div>
                                <div className="bg-gradient-to-br from-indigo-50 to-purple-50 p-6 rounded-[2rem] border border-indigo-100/50 print:border-2 print:border-slate-200">
                                    <div className="flex items-center gap-3 text-amber-600 mb-4">
                                        <div className="p-2 bg-amber-100 rounded-xl"><Clock className="w-5 h-5" /></div>
                                        <span className="text-xs font-black uppercase tracking-widest">Total Subjects</span>
                                    </div>
                                    <div className="text-4xl font-black text-slate-900">{reportData.subjects.length}</div>
                                </div>
                            </div>

                            {/* Table */}
                            <div className="overflow-x-auto rounded-[2rem] border border-slate-100 print:rounded-none mt-8">
                                <table className="w-full text-left border-collapse min-w-[800px]">
                                    <thead>
                                        <tr className="bg-slate-50 print:bg-slate-100 border-b border-slate-100 print:border-slate-300">
                                            <th className="p-6 text-[10px] font-black uppercase tracking-widest text-slate-400">Subject</th>
                                            <th className="p-6 text-[10px] font-black uppercase tracking-widest text-slate-400 text-center">C.A Score</th>
                                            <th className="p-6 text-[10px] font-black uppercase tracking-widest text-slate-400 text-center">Exam Score</th>
                                            <th className="p-6 text-[10px] font-black uppercase tracking-widest text-slate-400 text-center bg-indigo-50/30 print:bg-indigo-50">Total Marks</th>
                                            <th className="p-6 text-[10px] font-black uppercase tracking-widest text-slate-400 text-center">Grade</th>
                                            <th className="p-6 text-[10px] font-black uppercase tracking-widest text-slate-400">Teacher's Remark</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-50 print:divide-slate-200">
                                        {reportData.subjects.map((sub) => (
                                            <tr key={sub.id} className="hover:bg-slate-50/50 transition-colors group">
                                                <td className="p-6">
                                                    <span className="font-bold text-slate-900">{sub.subject}</span>
                                                </td>
                                                <td className="p-6 text-center font-medium text-slate-600">{sub.testScore}</td>
                                                <td className="p-6 text-center font-medium text-slate-600">{sub.examScore}</td>
                                                <td className="p-6 text-center font-black text-indigo-600 bg-indigo-50/30 print:bg-indigo-50 group-hover:bg-indigo-50 transition-colors">
                                                    {sub.totalMarks}
                                                </td>
                                                <td className="p-6 text-center">
                                                    <span className={`inline-flex items-center justify-center w-10 h-10 rounded-xl font-black text-lg ${
                                                        sub.grade === 'A' || sub.grade === 'A+' ? 'bg-emerald-100 text-emerald-700' :
                                                        sub.grade === 'B' ? 'bg-blue-100 text-blue-700' :
                                                        sub.grade === 'C' ? 'bg-amber-100 text-amber-700' :
                                                        sub.grade === 'D' || sub.grade === 'E' ? 'bg-orange-100 text-orange-700' :
                                                        'bg-red-100 text-red-700'
                                                    }`}>
                                                        {sub.grade}
                                                    </span>
                                                </td>
                                                <td className="p-6 text-sm font-bold text-slate-500">{sub.remark}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                            
                            <div className="hidden print:block mt-16 pt-8 border-t border-slate-200 text-center">
                                <p className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-10">Official Academic Record</p>
                                <div className="flex justify-between px-20">
                                    <div className="w-64 border-t-2 border-slate-900 pt-2"><span className="text-xs font-black uppercase tracking-widest">Principal's Signature</span></div>
                                    <div className="w-64 border-t-2 border-slate-900 pt-2"><span className="text-xs font-black uppercase tracking-widest">Date</span></div>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="flex flex-col items-center justify-center py-20 text-center border-2 border-dashed border-slate-100 rounded-3xl">
                            <FileText className="w-16 h-16 text-slate-200 mb-4" />
                            <h3 className="text-slate-800 font-bold mb-1">No Records Found</h3>
                            <p className="text-xs text-slate-400 font-medium">Your report card for {selectedTerm} is not ready yet or no exams were recorded.</p>
                        </div>
                    )}
                </div>
            </div>
            
            {/* Print Styles for Hiding specific non-content boundaries are injected via Tailwind's print: prefix */}
        </div>
    );
}
