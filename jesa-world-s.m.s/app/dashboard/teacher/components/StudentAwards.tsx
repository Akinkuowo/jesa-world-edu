"use client";

import { useState, useEffect } from "react";
import {
    Award,
    Trophy,
    Medal,
    ChevronDown,
    Users,
    BookOpen,
    FilterX,
    Star,
    TrendingUp,
    Loader2,
    ArrowLeft,
    FileText,
    Check
} from "lucide-react";

interface Result {
    id: string;
    subject: string;
    class: string;
    marks: number;
    term: string;
    student: {
        firstName: string;
        lastName: string;
        studentId: string;
    };
}

interface TeacherData {
    subjects: string[];
    classes: string[];
}

const TERMS = ["First Term", "Second Term", "Third Term"];

const MEDAL_COLORS = [
    { ring: "ring-amber-400", bg: "bg-amber-50", text: "text-amber-600", icon: "text-amber-400", label: "bg-gradient-to-br from-amber-400 to-amber-500" },
    { ring: "ring-slate-300", bg: "bg-slate-50", text: "text-slate-600", icon: "text-slate-400", label: "bg-gradient-to-br from-slate-400 to-slate-500" },
    { ring: "ring-orange-300", bg: "bg-orange-50", text: "text-orange-600", icon: "text-orange-400", label: "bg-gradient-to-br from-orange-400 to-orange-500" },
];

function RankBadge({ rank }: { rank: number }) {
    if (rank === 1) return (
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-amber-400 to-amber-500 flex items-center justify-center shadow-lg shadow-amber-400/30">
            <Trophy className="w-5 h-5 text-white" />
        </div>
    );
    if (rank === 2) return (
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-slate-400 to-slate-500 flex items-center justify-center shadow-lg shadow-slate-400/30">
            <Medal className="w-5 h-5 text-white" />
        </div>
    );
    if (rank === 3) return (
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-orange-400 to-orange-500 flex items-center justify-center shadow-lg shadow-orange-400/30">
            <Medal className="w-5 h-5 text-white" />
        </div>
    );
    return (
        <div className="w-9 h-9 rounded-xl bg-slate-100 flex items-center justify-center text-slate-500 font-black text-sm">
            {rank}
        </div>
    );
}

function ScoreBar({ score, maxScore = 100 }: { score: number, maxScore?: number }) {
    const pct = Math.min(100, (score / maxScore) * 100);
    const color = pct >= 70 ? "bg-emerald-500" : pct >= 50 ? "bg-amber-400" : "bg-red-400";
    return (
        <div className="flex-1 bg-slate-100 rounded-full h-2 overflow-hidden">
            <div className={`h-full ${color} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
        </div>
    );
}

export default function StudentAwards() {
    const [teacherData, setTeacherData] = useState<TeacherData>({ subjects: [], classes: [] });
    const [results, setResults] = useState<Result[]>([]);
    const [loading, setLoading] = useState(false);

    const [selectedSubject, setSelectedSubject] = useState<string>("");
    const [selectedClass, setSelectedClass] = useState<string>("");
    const [selectedTerm, setSelectedTerm] = useState<string>("");
    const [activeSubject, setActiveSubject] = useState<string | null>(null);
    const [selectedResult, setSelectedResult] = useState<any | null>(null);
    const [detailsLoading, setDetailsLoading] = useState(false);
    const [editedMarks, setEditedMarks] = useState<Record<string, number>>({});
    const [editedTestScore, setEditedTestScore] = useState<number>(0);
    const [savingGrades, setSavingGrades] = useState(false);

    const fetchData = async (subject?: string, studentClass?: string, term?: string) => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const url = new URL(`${process.env.NEXT_PUBLIC_API_URL}/teacher/awards`);
            if (subject) url.searchParams.set("subject", subject);
            if (studentClass) url.searchParams.set("class", studentClass);
            if (term) url.searchParams.set("term", term);

            const res = await fetch(url.toString(), {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setResults(data);
            }
        } catch (err) {
            console.error("Failed to fetch awards:", err);
        } finally {
            setLoading(false);
        }
    };

    const fetchDetailedResult = async (resultId: string) => {
        setDetailsLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/awards/result/${resultId}`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setSelectedResult(data);
                
                // Initialize editedMarks for theory questions
                const initialMarks: Record<string, number> = {};
                data.answers.forEach((ans: any) => {
                    if (ans.question.type === 'THEORY') {
                        initialMarks[ans.id] = ans.marks || 0;
                    }
                });
                setEditedMarks(initialMarks);
                setEditedTestScore(data.testScore || 0);
            }
        } catch (error) {
            console.error("Fetch detailed result error:", error);
        } finally {
            setDetailsLoading(false);
        }
    };

    const handleSaveGrades = async () => {
        if (!selectedResult) return;
        setSavingGrades(true);
        try {
            const token = localStorage.getItem("token");
            const theoryGrades = Object.entries(editedMarks).map(([answerId, marks]) => ({
                answerId,
                marks
            }));

            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/awards/grade`, {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${token}` 
                },
                body: JSON.stringify({
                    resultId: selectedResult.id,
                    theoryGrades,
                    testScore: editedTestScore
                })
            });

            if (res.ok) {
                // Refresh the current details view and the main results list
                await fetchDetailedResult(selectedResult.id);
                fetchData(selectedSubject || undefined, selectedClass || undefined, selectedTerm || undefined);
            }
        } catch (error) {
            console.error("Save grades error:", error);
        } finally {
            setSavingGrades(false);
        }
    };

    useEffect(() => {
        const fetchTeacherData = async () => {
            try {
                const token = localStorage.getItem("token");
                const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/my-data`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                if (res.ok) {
                    const data = await res.json();
                    setTeacherData(data);
                }
            } catch (err) {
                console.error("Failed to fetch teacher data:", err);
            }
        };
        fetchTeacherData();
        fetchData();
    }, []);

    const handleFilter = () => {
        fetchData(selectedSubject || undefined, selectedClass || undefined, selectedTerm || undefined);
    };

    const handleClearFilters = () => {
        setSelectedSubject("");
        setSelectedClass("");
        setSelectedTerm("");
        fetchData();
    };

    // Group results by subject + class
    const grouped: Record<string, Result[]> = {};
    results.forEach(r => {
        const key = `${r.subject}__${r.class}`;
        if (!grouped[key]) grouped[key] = [];
        grouped[key].push(r);
    });
    // Sort each group by marks descending (already sorted by API, but just in case)
    Object.keys(grouped).forEach(k => grouped[k].sort((a, b) => b.marks - a.marks));

    const groupKeys = Object.keys(grouped).sort();
    const hasFilters = selectedClass || selectedTerm;

    const handleSubjectClick = (subj: string) => {
        setActiveSubject(subj);
        setSelectedSubject(subj);
        fetchData(subj, selectedClass || undefined, selectedTerm || undefined);
    };

    const handleBackToGrid = () => {
        setActiveSubject(null);
        setSelectedSubject("");
        setSelectedClass("");
        setSelectedTerm("");
        fetchData();
    };

    return (
        <div className="flex flex-col gap-8">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <div className="flex items-center gap-3 mb-1">
                        {activeSubject && (
                            <button 
                                onClick={handleBackToGrid}
                                className="p-2 bg-slate-100 hover:bg-slate-200 rounded-xl transition-all text-slate-600 active:scale-95"
                            >
                                <ArrowLeft className="w-5 h-5" />
                            </button>
                        )}
                        <h2 className="text-3xl font-black text-slate-800 tracking-tight flex items-center gap-3">
                            {activeSubject ? activeSubject : "Student Awards"}
                            <span className="text-[10px] font-bold text-slate-400 border border-slate-200 px-2 py-0.5 rounded-full">v1.1</span>
                        </h2>
                    </div>
                    <p className="text-slate-500 text-sm font-medium">
                        {activeSubject 
                            ? `Detailed rankings for students offering ${activeSubject}`
                            : "Select a subject to view student rankings and performances"
                        }
                    </p>
                </div>
                {!activeSubject && (
                    <div className="flex items-center space-x-2 bg-amber-50 border border-amber-200 px-5 py-3 rounded-2xl">
                        <Trophy className="w-5 h-5 text-amber-500" />
                        <span className="font-black text-amber-700 text-sm">{results.length} Records</span>
                    </div>
                )}
            </div>

            {!activeSubject ? (
                /* Subject Grid View */
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {teacherData.subjects.length > 0 ? (
                        teacherData.subjects.map((subj) => {
                            const subjResults = results.filter(r => r.subject === subj);
                            const uniqueStudents = new Set(subjResults.map(r => r.student.studentId)).size;
                            const avgScore = subjResults.length > 0 
                                ? Math.round(subjResults.reduce((acc, r) => acc + r.marks, 0) / subjResults.length)
                                : 0;
                            const topScore = subjResults.length > 0 
                                ? Math.max(...subjResults.map(r => r.marks))
                                : 0;
                            
                            return (
                                <div 
                                    key={subj} 
                                    onClick={() => handleSubjectClick(subj)}
                                    className="group bg-white rounded-[2.5rem] border border-slate-100 p-8 shadow-sm hover:shadow-xl hover:shadow-indigo-500/10 transition-all cursor-pointer relative overflow-hidden"
                                >
                                    <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-50/50 rounded-bl-[5rem] -mr-10 -mt-10 group-hover:scale-110 transition-transform duration-500 -z-0" />
                                    
                                    <div className="relative z-10">
                                        <div className="w-14 h-14 bg-indigo-600 rounded-2xl flex items-center justify-center mb-6 shadow-lg shadow-indigo-600/20 group-hover:scale-110 transition-transform">
                                            <BookOpen className="w-7 h-7 text-white" />
                                        </div>
                                        
                                        <h3 className="text-xl font-black text-slate-800 mb-2 truncate">{subj}</h3>
                                        
                                        <div className="grid grid-cols-2 gap-4 mt-6 pt-6 border-t border-slate-50">
                                            <div className="flex flex-col">
                                                <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Students</span>
                                                <span className="text-lg font-black text-slate-700">{uniqueStudents}</span>
                                            </div>
                                            <div className="flex flex-col">
                                                <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Avg Score</span>
                                                <span className="text-lg font-black text-emerald-600">{avgScore} pts</span>
                                            </div>
                                            <div className="flex flex-col">
                                                <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Top Score</span>
                                                <span className="text-lg font-black text-amber-500">{topScore} pts</span>
                                            </div>
                                            <div className="flex flex-col">
                                                <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Status</span>
                                                <span className="text-xs font-bold text-indigo-500 bg-indigo-50 px-2 py-0.5 rounded-full mt-1 w-fit">Active</span>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="mt-8 flex items-center justify-between text-indigo-600 font-bold text-sm">
                                        <span>View Rankings</span>
                                        <TrendingUp className="w-4 h-4 transform group-hover:translate-x-1 transition-transform" />
                                    </div>
                                </div>
                            );
                        })
                    ) : (
                        <div className="col-span-full flex flex-col items-center justify-center py-20 bg-white rounded-[2rem] border border-slate-100 text-center">
                            <BookOpen className="w-16 h-16 text-slate-200 mb-4" />
                            <h3 className="text-xl font-black text-slate-800 mb-2">No Subjects Assigned</h3>
                            <p className="text-slate-500 font-medium">You don't have any subjects assigned to your profile yet.</p>
                        </div>
                    )}
                </div>
            ) : (
                /* Detail View */
                <>
                    {/* Filters for Detail View */}
                    <div className="bg-white rounded-[2rem] border border-slate-100 p-6 shadow-sm">
                        <div className="flex flex-col md:flex-row gap-4 items-end">
                            {/* Class */}
                            <div className="flex-1 space-y-2">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Class Filter</label>
                                <div className="relative">
                                    <Users className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                                    <select
                                        className="w-full bg-slate-50 border-0 pl-10 pr-10 py-3.5 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500/30 font-bold text-slate-700 text-sm appearance-none cursor-pointer"
                                        value={selectedClass}
                                        onChange={e => setSelectedClass(e.target.value)}
                                    >
                                        <option value="">All Classes</option>
                                        {teacherData.classes.map(c => (
                                            <option key={c} value={c}>{c}</option>
                                        ))}
                                    </select>
                                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                                </div>
                            </div>

                            {/* Term */}
                            <div className="flex-1 space-y-2">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Term Filter</label>
                                <div className="relative">
                                    <Star className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                                    <select
                                        className="w-full bg-slate-50 border-0 pl-10 pr-10 py-3.5 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500/30 font-bold text-slate-700 text-sm appearance-none cursor-pointer"
                                        value={selectedTerm}
                                        onChange={e => setSelectedTerm(e.target.value)}
                                    >
                                        <option value="">All Terms</option>
                                        {TERMS.map(t => (
                                            <option key={t} value={t}>{t}</option>
                                        ))}
                                    </select>
                                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                                </div>
                            </div>

                            <div className="flex items-center space-x-3">
                                <button
                                    onClick={handleFilter}
                                    className="bg-indigo-600 hover:bg-indigo-700 text-white px-7 py-3.5 rounded-xl font-black text-sm transition-all shadow-lg shadow-indigo-600/20 active:scale-95 flex items-center space-x-2"
                                >
                                    <TrendingUp className="w-4 h-4" />
                                    <span>Apply Filters</span>
                                </button>
                                {hasFilters && (
                                    <button
                                        onClick={() => { setSelectedClass(""); setSelectedTerm(""); fetchData(activeSubject); }}
                                        className="bg-slate-100 hover:bg-slate-200 text-slate-600 px-5 py-3.5 rounded-xl font-bold text-sm transition-all active:scale-95 flex items-center space-x-2"
                                    >
                                        <FilterX className="w-4 h-4" />
                                        <span>Reset</span>
                                    </button>
                                )}
                            </div>
                        </div>
                    </div>

                    {loading ? (
                        <div className="flex flex-col items-center justify-center h-80 bg-white rounded-[2rem] border border-slate-100 shadow-sm text-center">
                            <Loader2 className="w-10 h-10 text-indigo-500 animate-spin mb-4" />
                            <p className="text-slate-500 font-bold">Fetching results for {activeSubject}...</p>
                        </div>
                    ) : groupKeys.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-24 bg-white rounded-[2rem] border border-slate-100 shadow-sm text-center">
                            <Award className="w-16 h-16 text-slate-200 mb-6" />
                            <h3 className="text-xl font-black text-slate-800 mb-2">No Students Found</h3>
                            <p className="text-slate-500 font-medium max-w-sm mx-auto">
                                No exam results recorded for {activeSubject} with the current filters.
                            </p>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                            {groupKeys.map(key => {
                                const [subject, cls] = key.split("__");
                                const groupResults = grouped[key];
                                const topScore = groupResults[0]?.marks ?? 100;

                                return (
                                    <div key={key} className="bg-white rounded-[2rem] border border-slate-100 p-8 shadow-sm hover:shadow-md transition-shadow">
                                        <div className="flex items-start justify-between mb-7">
                                            <div>
                                                <div className="flex items-center space-x-2 mb-1">
                                                    <span className="px-3 py-1 bg-indigo-50 text-indigo-600 rounded-lg text-[10px] font-black uppercase tracking-wider">{cls}</span>
                                                    <span className="px-3 py-1 bg-emerald-50 text-emerald-600 rounded-lg text-[10px] font-black uppercase tracking-wider">{groupResults.length} Students</span>
                                                </div>
                                                <h3 className="text-xl font-black text-slate-800 mt-2 tracking-tight">{cls} Rankings</h3>
                                            </div>
                                            <div className="w-12 h-12 bg-amber-50 rounded-2xl flex items-center justify-center">
                                                <Trophy className="w-6 h-6 text-amber-400" />
                                            </div>
                                        </div>

                                        <div className="flex items-end justify-center gap-3 mb-8">
                                            {groupResults[1] && (
                                                <div className="flex flex-col items-center gap-2">
                                                    <div className="w-12 h-12 bg-slate-100 rounded-2xl flex items-center justify-center text-slate-700 font-black text-lg ring-2 ring-slate-200">
                                                        {groupResults[1].student.firstName.charAt(0)}
                                                    </div>
                                                    <div className="text-center">
                                                        <p className="text-xs font-black text-slate-700 leading-none truncate max-w-[80px]">{groupResults[1].student.firstName}</p>
                                                        <p className="text-[10px] text-slate-400 font-black mt-1">{groupResults[1].marks}%</p>
                                                    </div>
                                                    <div className="w-12 h-12 bg-slate-100 rounded-t-xl flex items-end justify-center pb-1">
                                                        <span className="text-slate-400 font-black text-lg">2</span>
                                                    </div>
                                                </div>
                                            )}
                                            <div className="flex flex-col items-center gap-2">
                                                <div className="w-14 h-14 bg-amber-50 rounded-2xl flex items-center justify-center text-amber-600 font-black text-xl ring-2 ring-amber-300">
                                                    {groupResults[0].student.firstName.charAt(0)}
                                                </div>
                                                <div className="text-center">
                                                    <p className="text-xs font-black text-slate-700 leading-none truncate max-w-[100px]">{groupResults[0].student.firstName}</p>
                                                    <p className="text-xs text-amber-500 font-black mt-1">{groupResults[0].marks}%</p>
                                                </div>
                                                <div className="w-14 h-20 bg-amber-300 rounded-t-xl flex items-end justify-center pb-2">
                                                    <span className="text-amber-800 font-black text-xl">1</span>
                                                </div>
                                            </div>
                                            {groupResults[2] && (
                                                <div className="flex flex-col items-center gap-2">
                                                    <div className="w-12 h-12 bg-orange-50 rounded-2xl flex items-center justify-center text-orange-600 font-black text-lg ring-2 ring-orange-200">
                                                        {groupResults[2].student.firstName.charAt(0)}
                                                    </div>
                                                    <div className="text-center">
                                                        <p className="text-xs font-black text-slate-700 leading-none truncate max-w-[80px]">{groupResults[2].student.firstName}</p>
                                                        <p className="text-[10px] text-orange-400 font-black mt-1">{groupResults[2].marks}%</p>
                                                    </div>
                                                    <div className="w-12 h-8 bg-orange-100 rounded-t-xl flex items-end justify-center pb-0.5">
                                                        <span className="text-orange-500 font-black text-lg">3</span>
                                                    </div>
                                                </div>
                                            )}
                                        </div>

                                        <div className="space-y-2 border-t border-slate-50 pt-6">
                                            {groupResults.map((r, idx) => (
                                                <div key={r.id} className="flex items-center gap-4 p-3 rounded-2xl hover:bg-slate-50 transition-colors group">
                                                    <RankBadge rank={idx + 1} />
                                                    <div className="flex-1 min-w-0">
                                                        <button 
                                                            onClick={() => fetchDetailedResult(r.id)}
                                                            className="text-left block w-full group"
                                                        >
                                                            <p className="font-black text-slate-800 text-sm truncate group-hover:text-indigo-600 transition-colors">
                                                                {r.student.firstName} {r.student.lastName}
                                                            </p>
                                                            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wide">{r.student.studentId}</p>
                                                        </button>
                                                    </div>
                                                    <div className="flex items-center gap-3 w-36">
                                                        <ScoreBar score={r.marks} maxScore={topScore > 0 ? topScore : 100} />
                                                        <span className="text-sm font-black text-slate-700 w-12 text-right">
                                                            {r.marks} pts
                                                        </span>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </>
            )}

            {/* Submission Details Modal */}
            {selectedResult && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4">
                    <div className="bg-white rounded-[3rem] w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-300">
                        {/* Modal Header */}
                        <div className="p-8 border-b border-slate-100 flex items-center justify-between bg-white sticky top-0 z-10">
                            <div className="flex items-center gap-6">
                                <div className="w-16 h-16 bg-indigo-600 rounded-[1.5rem] flex items-center justify-center text-white shadow-xl shadow-indigo-600/20">
                                    <Trophy className="w-8 h-8" />
                                </div>
                                <div>
                                    <h3 className="text-2xl font-black text-slate-900 tracking-tight">
                                        {selectedResult.student.firstName} {selectedResult.student.lastName}
                                    </h3>
                                    <div className="flex items-center gap-3 mt-1 text-sm font-bold text-slate-400 uppercase tracking-widest">
                                        <span>{selectedResult.student.studentId}</span>
                                        <span className="w-1 h-1 bg-slate-300 rounded-full" />
                                        <span>{selectedResult.student.studentClass}</span>
                                        <span className="w-1 h-1 bg-slate-300 rounded-full" />
                                        <span className="text-indigo-600">{selectedResult.subject}</span>
                                    </div>
                                </div>
                            </div>
                            <div className="flex flex-col items-end">
                                <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Total MCQ Score</span>
                                <span className="text-4xl font-black text-indigo-600">{selectedResult.marks} pts</span>
                            </div>
                        </div>

                        {/* Modal Content */}
                        <div className="flex-1 overflow-y-auto p-10 space-y-10 scrollbar-hide bg-slate-50/30">
                            {/* Summary Cards */}
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm">
                                    <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-4">Exam Info</h4>
                                    <div className="space-y-3">
                                        <div className="flex justify-between">
                                            <span className="text-sm font-bold text-slate-500">Term</span>
                                            <span className="text-sm font-black text-slate-800">{selectedResult.term}</span>
                                        </div>
                                        <div className="flex justify-between">
                                            <span className="text-sm font-bold text-slate-500">Date</span>
                                            <span className="text-sm font-black text-slate-800">{new Date(selectedResult.createdAt).toLocaleDateString()}</span>
                                        </div>
                                    </div>
                                </div>
                                <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm">
                                    <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-4">Submission Stats</h4>
                                    <div className="space-y-3">
                                        <div className="flex justify-between">
                                            <span className="text-sm font-bold text-slate-500">Total Questions</span>
                                            <span className="text-sm font-black text-slate-800">{selectedResult.answers.length}</span>
                                        </div>
                                        <div className="flex justify-between">
                                            <span className="text-sm font-bold text-slate-500">Theory Questions</span>
                                            <span className="text-sm font-black text-indigo-600">{selectedResult.answers.filter((a: any) => a.question.type === 'THEORY').length}</span>
                                        </div>
                                    </div>
                                </div>

                                {/* Manual Test Score Entry (if not Mock/WAEC/NECO) */}
                                {!(
                                    selectedResult.subject.toLowerCase().includes("mock") || 
                                    selectedResult.subject.toLowerCase().includes("waec") || 
                                    selectedResult.subject.toLowerCase().includes("neco")
                                ) ? (
                                    <div className="bg-white p-6 rounded-3xl border-2 border-indigo-500/20 shadow-xl shadow-indigo-600/5 flex flex-col justify-center">
                                        <div className="flex items-center justify-between mb-2">
                                            <h4 className="text-[10px] font-black text-indigo-600 uppercase tracking-widest">Continuous Assessment</h4>
                                            <span className="text-[10px] font-bold text-slate-400">MAX 40</span>
                                        </div>
                                        <div className="flex items-center gap-4">
                                            <div className="flex-1">
                                                <p className="text-sm font-black text-slate-800">Test Score</p>
                                                <p className="text-[10px] text-slate-400 font-bold">Manual Entry</p>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <input 
                                                    type="number"
                                                    value={editedTestScore}
                                                    onChange={(e) => setEditedTestScore(parseFloat(e.target.value) || 0)}
                                                    max={40}
                                                    className="w-24 px-4 py-3 bg-indigo-50 border border-indigo-100 rounded-2xl text-center font-black text-indigo-700 text-xl focus:bg-white focus:border-indigo-500 outline-none transition-all"
                                                />
                                                <span className="text-sm font-bold text-slate-400">/ 40</span>
                                            </div>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="bg-slate-50 p-6 rounded-3xl border border-slate-200 flex flex-col justify-center items-center text-center">
                                        <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">External Exam Mode</span>
                                        <p className="text-xs font-bold text-slate-500">Test Score not applicable for {selectedResult.subject}</p>
                                    </div>
                                )}
                            </div>

                            {/* Detailed Answers Sectioned */}
                            <div className="space-y-12">
                                {/* Objective Questions Section */}
                                {selectedResult.answers.filter((a: any) => a.question.type === 'MCQ').length > 0 && (
                                    <div className="space-y-8">
                                        <div className="flex items-center gap-3 border-b border-slate-100 pb-4">
                                            <div className="w-10 h-10 bg-emerald-50 rounded-xl flex items-center justify-center text-emerald-600">
                                                <Check className="w-5 h-5" />
                                            </div>
                                            <h4 className="text-xl font-black text-slate-800 tracking-tight">Objective Questions</h4>
                                        </div>
                                        <div className="grid grid-cols-1 gap-6">
                                            {selectedResult.answers
                                                .filter((ans: any) => ans.question.type === 'MCQ')
                                                .map((ans: any, idx: number) => {
                                                    const choiceIdx = ans.question.answer.toUpperCase().charCodeAt(0) - 65;
                                                    const correctText = ans.question.options[choiceIdx];
                                                    const isCorrect = ans.answerText.trim().toLowerCase() === correctText?.trim().toLowerCase();
                                                    
                                                    return (
                                                        <div key={ans.id} className="bg-white rounded-[2rem] border border-slate-100 overflow-hidden shadow-sm hover:shadow-md transition-shadow">
                                                            <div className="p-6 md:p-8">
                                                                <div className="flex items-center justify-between mb-4">
                                                                    <span className="px-3 py-1 bg-slate-50 text-[10px] font-black text-slate-400 rounded-lg uppercase tracking-widest">
                                                                        Question {idx + 1}
                                                                    </span>
                                                                    <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-full ${
                                                                        isCorrect ? 'bg-emerald-50 text-emerald-600' : 'bg-rose-50 text-rose-600'
                                                                    }`}>
                                                                        {isCorrect ? `+${ans.question.marks} pts` : '0 pts'}
                                                                    </span>
                                                                </div>
                                                                
                                                                <div 
                                                                    className="text-lg font-bold text-slate-800 mb-6 prose prose-slate max-w-none"
                                                                    dangerouslySetInnerHTML={{ __html: ans.question.question }}
                                                                />

                                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                                    <div className="space-y-2">
                                                                        <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Student's Choice:</span>
                                                                        <div className={`p-4 rounded-xl border ${
                                                                            isCorrect ? 'bg-emerald-50 border-emerald-500/20 text-emerald-900' : 'bg-rose-50 border-rose-500/20 text-rose-900'
                                                                        } font-bold text-sm`}>
                                                                            {ans.answerText}
                                                                        </div>
                                                                    </div>
                                                                    {!isCorrect && (
                                                                        <div className="space-y-2">
                                                                            <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Correct Answer:</span>
                                                                            <div className="p-4 rounded-xl border bg-slate-50 border-slate-200 text-slate-700 font-bold text-sm">
                                                                                {correctText}
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        </div>
                                                    );
                                                })}
                                        </div>
                                    </div>
                                )}

                                {/* Theory Questions Section */}
                                {selectedResult.answers.filter((a: any) => a.question.type === 'THEORY').length > 0 && (
                                    <div className="space-y-8">
                                        <div className="flex items-center gap-3 border-b border-slate-100 pb-4">
                                            <div className="w-10 h-10 bg-indigo-50 rounded-xl flex items-center justify-center text-indigo-600">
                                                <FileText className="w-5 h-5" />
                                            </div>
                                            <h4 className="text-xl font-black text-slate-800 tracking-tight">Theory Questions</h4>
                                        </div>
                                        <div className="grid grid-cols-1 gap-6">
                                            {selectedResult.answers
                                                .filter((ans: any) => ans.question.type === 'THEORY')
                                                .map((ans: any, idx: number) => (
                                                    <div key={ans.id} className="bg-white rounded-[2rem] border border-slate-100 overflow-hidden shadow-sm hover:shadow-md transition-shadow">
                                                        <div className="p-6 md:p-8">
                                                            <div className="flex items-center justify-between mb-4">
                                                                <span className="px-3 py-1 bg-slate-50 text-[10px] font-black text-slate-400 rounded-lg uppercase tracking-widest">
                                                                    Theory Question {idx + 1}
                                                                </span>
                                                                <div className="flex items-center gap-3">
                                                                    <span className="text-xs font-bold text-slate-400">Award Score:</span>
                                                                    <div className="flex items-center gap-2">
                                                                        <input 
                                                                            type="number"
                                                                            value={editedMarks[ans.id] ?? 0}
                                                                            onChange={(e) => setEditedMarks(prev => ({
                                                                                ...prev,
                                                                                [ans.id]: parseFloat(e.target.value) || 0
                                                                            }))}
                                                                            max={ans.question.marks}
                                                                            className="w-20 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-center font-black text-indigo-600 focus:bg-white focus:border-indigo-500 outline-none transition-all"
                                                                        />
                                                                        <span className="text-xs font-bold text-slate-400">/ {ans.question.marks} pts</span>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                            
                                                            <div 
                                                                className="text-lg font-bold text-slate-800 mb-6 prose prose-slate max-w-none"
                                                                dangerouslySetInnerHTML={{ __html: ans.question.question }}
                                                            />

                                                            <div className="space-y-2">
                                                                <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Student's Answer:</span>
                                                                <div className="p-6 rounded-2xl bg-slate-50 border border-slate-100 text-slate-800 font-medium text-base whitespace-pre-wrap leading-relaxed shadow-inner">
                                                                    {ans.answerText || "No answer provided"}
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Modal Footer with Save Actions */}
                        <div className="p-8 border-t border-slate-100 bg-white sticky bottom-0 z-10 flex gap-4">
                            <button 
                                onClick={() => setSelectedResult(null)}
                                className="flex-1 bg-slate-100 text-slate-700 font-black py-4 rounded-2xl hover:bg-slate-200 transition-all active:scale-[0.98]"
                            >
                                Close Review
                            </button>
                            {selectedResult.answers.some((a: any) => a.question.type === 'THEORY') && (
                                <button 
                                    onClick={handleSaveGrades}
                                    disabled={savingGrades}
                                    className="flex-[2] bg-indigo-600 text-white font-black py-4 rounded-2xl hover:bg-indigo-700 shadow-xl shadow-indigo-600/20 transition-all flex items-center justify-center gap-3 active:scale-[0.98] disabled:opacity-50"
                                >
                                    {savingGrades ? <Loader2 className="w-5 h-5 animate-spin" /> : <Check className="w-5 h-5" />}
                                    {savingGrades ? 'Saving Grades...' : 'Save All Theory Grades'}
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {detailsLoading && (
                <div className="fixed inset-0 z-[150] flex items-center justify-center bg-slate-900/10 backdrop-blur-[2px]">
                    <div className="bg-white p-6 rounded-3xl shadow-xl flex items-center gap-4">
                        <Loader2 className="w-6 h-6 text-indigo-600 animate-spin" />
                        <span className="font-bold text-slate-700">Loading Submission...</span>
                    </div>
                </div>
            )}
        </div>
    );
}
