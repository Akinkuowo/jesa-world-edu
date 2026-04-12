"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, Clock, FileText, CheckCircle, CheckCircle2, User, ChevronRight, X, Send } from "lucide-react";

interface Assignment {
    id: string;
    title: string;
    description: string;
    subject: string;
    dueDate: string;
    teacherName: string;
    hasSubmitted: boolean;
    submissionContent: string | null;
    submittedAt: string | null;
    score: number | null;
}

export default function StudentAssignments() {
    const router = useRouter();
    const [assignments, setAssignments] = useState<Assignment[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedAssignment, setSelectedAssignment] = useState<Assignment | null>(null);
    const [submissionText, setSubmissionText] = useState("");
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [toast, setToast] = useState<{ show: boolean, message: string, type: 'success' | 'error' }>({ show: false, message: '', type: 'success' });
    const [activeTab, setActiveTab] = useState<'pending' | 'completed'>('pending');

    useEffect(() => {
        fetchAssignments();
    }, []);

    const fetchAssignments = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/student/assignments`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                setAssignments(await res.json());
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = async () => {
        if (!selectedAssignment || !submissionText.trim()) return;
        setIsSubmitting(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/student/assignments/${selectedAssignment.id}/submit`, {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ content: submissionText })
            });

            if (res.ok) {
                const submission = await res.json();
                setToast({ show: true, message: "Assignment submitted successfully!", type: "success" });
                setTimeout(() => setToast({ show: false, message: '', type: 'success' }), 3000);
                setSelectedAssignment(null);
                setSubmissionText("");
                fetchAssignments(); // Refresh list to update status
            } else {
                setToast({ show: true, message: "Failed to submit assignment", type: "error" });
                setTimeout(() => setToast({ show: false, message: '', type: 'success' }), 3000);
            }
        } catch (err) {
            console.error(err);
        } finally {
            setIsSubmitting(false);
        }
    };

    const pendingAssignments = assignments.filter(a => !a.hasSubmitted);
    const completedAssignments = assignments.filter(a => a.hasSubmitted);

    return (
        <div className="min-h-screen bg-[#f1f3f6] text-slate-900 font-sans pb-20">
            {toast.show && (
                <div className={`fixed top-4 right-4 z-50 px-6 py-4 rounded-xl shadow-xl border font-bold animate-in slide-in-from-top-2 ${toast.type === 'success' ? 'bg-emerald-50 text-emerald-800 border-emerald-200' : 'bg-red-50 text-red-800 border-red-200'}`}>
                    {toast.message}
                </div>
            )}

            <div className="bg-indigo-700 h-48 lg:h-64 w-full relative overflow-hidden">
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
                        <div className="text-white">
                            <h1 className="text-3xl lg:text-4xl font-black tracking-tight mb-1">My Assignments</h1>
                            <p className="opacity-80 font-medium text-sm lg:text-base">View and submit pending coursework</p>
                        </div>
                    </div>
                </div>
            </div>

            <div className="max-w-7xl mx-auto px-6 lg:px-10 -mt-8 relative z-20">
                <div className="bg-white rounded-[2rem] p-8 shadow-xl shadow-slate-200/60 border border-white min-h-[60vh]">
                    <div className="flex bg-slate-100 p-1.5 rounded-2xl w-fit mb-8">
                        <button onClick={() => setActiveTab('pending')} className={`px-8 py-3 rounded-xl text-sm font-black tracking-widest uppercase transition-all ${activeTab === 'pending' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-400 hover:text-slate-600'}`}>
                            Pending ({pendingAssignments.length})
                        </button>
                        <button onClick={() => setActiveTab('completed')} className={`px-8 py-3 rounded-xl text-sm font-black tracking-widest uppercase transition-all ${activeTab === 'completed' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-400 hover:text-slate-600'}`}>
                            Completed ({completedAssignments.length})
                        </button>
                    </div>

                    {loading ? (
                        <div className="flex justify-center py-20 text-slate-400 italic">Loading assignments...</div>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            {(activeTab === 'pending' ? pendingAssignments : completedAssignments).length > 0 ? (
                                (activeTab === 'pending' ? pendingAssignments : completedAssignments).map(assignment => (
                                    <div key={assignment.id} className="bg-slate-50 border border-slate-100 rounded-[2rem] p-6 hover:shadow-lg hover:-translate-y-1 transition-all cursor-pointer group flex flex-col" onClick={() => setSelectedAssignment(assignment)}>
                                        <div className="flex items-center justify-between mb-4">
                                            <span className="px-3 py-1 bg-indigo-100 text-indigo-700 rounded-full text-[10px] font-black uppercase tracking-widest">
                                                {assignment.subject}
                                            </span>
                                            {assignment.hasSubmitted ? (
                                                <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                                            ) : (
                                                <Clock className="w-5 h-5 text-amber-500" />
                                            )}
                                        </div>
                                        <h3 className="text-xl font-black text-slate-900 mb-2 truncate" title={assignment.title}>{assignment.title}</h3>
                                        <div className="flex items-center text-xs font-bold text-slate-500 mb-6 gap-2">
                                            <User className="w-3 h-3" />
                                            <span>{assignment.teacherName}</span>
                                        </div>
                                        <div className="mt-auto pt-4 border-t border-slate-200/60 flex items-center justify-between">
                                            <div>
                                                <p className="text-[9px] font-black uppercase tracking-[0.2em] text-slate-400 mb-0.5">Due Date</p>
                                                <p className="text-xs font-bold text-slate-700">{new Date(assignment.dueDate).toLocaleDateString()}</p>
                                            </div>
                                            <button className={`w-8 h-8 rounded-full flex items-center justify-center transition-colors ${assignment.hasSubmitted ? 'bg-emerald-100 text-emerald-600 group-hover:bg-emerald-200' : 'bg-indigo-100 text-indigo-600 group-hover:bg-indigo-600 group-hover:text-white'}`}>
                                                <ChevronRight className="w-4 h-4" />
                                            </button>
                                        </div>
                                    </div>
                                ))
                            ) : (
                                <div className="col-span-full py-20 flex flex-col items-center justify-center border-2 border-dashed border-slate-100 rounded-3xl">
                                    {activeTab === 'pending' ? (
                                        <>
                                            <CheckCircle className="w-16 h-16 text-emerald-200 mb-4" />
                                            <h3 className="text-slate-800 font-bold mb-1">All Caught Up!</h3>
                                            <p className="text-xs text-slate-400 font-medium">You have no pending assignments right now.</p>
                                        </>
                                    ) : (
                                        <>
                                            <FileText className="w-16 h-16 text-slate-200 mb-4" />
                                            <h3 className="text-slate-800 font-bold mb-1">No Completed Assignments</h3>
                                            <p className="text-xs text-slate-400 font-medium">Your submitted assignments will appear here.</p>
                                        </>
                                    )}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>

            {/* Assignment Detail & Submission Modal */}
            {selectedAssignment && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
                    <div className="bg-white w-full max-w-3xl max-h-[90vh] rounded-[2.5rem] flex flex-col shadow-2xl overflow-hidden scale-100 animate-in zoom-in-95 duration-200">
                        {/* Header */}
                        <div className="px-8 py-6 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                            <div>
                                <div className="flex items-center gap-2 mb-1">
                                    <span className="px-2.5 py-0.5 bg-indigo-100 text-indigo-700 rounded-full text-[10px] font-black uppercase tracking-widest">{selectedAssignment.subject}</span>
                                    {selectedAssignment.hasSubmitted && <span className="px-2.5 py-0.5 bg-emerald-100 text-emerald-700 rounded-full text-[10px] font-black uppercase tracking-widest flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> Submitted</span>}
                                </div>
                                <h2 className="text-2xl font-black text-slate-900 leading-tight">{selectedAssignment.title}</h2>
                            </div>
                            <button onClick={() => setSelectedAssignment(null)} className="p-2 hover:bg-slate-200 rounded-full transition-colors self-start">
                                <X className="w-5 h-5 text-slate-500" />
                            </button>
                        </div>
                        
                        {/* Body */}
                        <div className="flex-1 overflow-y-auto p-8 bg-white custom-scrollbar space-y-8">
                            <div className="flex items-center gap-6 pb-6 border-b border-slate-100">
                                <div>
                                    <p className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-1">Teacher</p>
                                    <p className="text-sm font-bold text-slate-800">{selectedAssignment.teacherName}</p>
                                </div>
                                <div className="w-px h-8 bg-slate-100" />
                                <div>
                                    <p className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-1">Due Date</p>
                                    <p className="text-sm font-bold text-slate-800">{new Date(selectedAssignment.dueDate).toLocaleString()}</p>
                                </div>
                                {selectedAssignment.hasSubmitted && selectedAssignment.score !== null && (
                                    <>
                                        <div className="w-px h-8 bg-slate-100" />
                                        <div>
                                            <p className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-1">Score</p>
                                            <p className="text-sm font-black text-indigo-600">{selectedAssignment.score} Points</p>
                                        </div>
                                    </>
                                )}
                            </div>

                            <div>
                                <h3 className="text-sm font-black text-slate-900 uppercase tracking-widest mb-4">Instructions</h3>
                                <div className="text-slate-600 leading-relaxed font-medium text-sm whitespace-pre-wrap bg-slate-50 p-6 rounded-2xl border border-slate-100">
                                    {selectedAssignment.description}
                                </div>
                            </div>

                            <div>
                                <h3 className="text-sm font-black text-slate-900 uppercase tracking-widest mb-4 flex items-center justify-between">
                                    {selectedAssignment.hasSubmitted ? "Your Submission" : "Complete Assignment"}
                                    {selectedAssignment.hasSubmitted && <span className="text-[9px] text-slate-400 tracking-normal normal-case">Submitted precisely at {new Date(selectedAssignment.submittedAt!).toLocaleString()}</span>}
                                </h3>
                                
                                {selectedAssignment.hasSubmitted ? (
                                    <div className="text-slate-700 leading-relaxed font-medium text-sm whitespace-pre-wrap bg-indigo-50/50 p-6 rounded-2xl border border-indigo-100">
                                        {selectedAssignment.submissionContent}
                                    </div>
                                ) : (
                                    <textarea 
                                        value={submissionText}
                                        onChange={(e) => setSubmissionText(e.target.value)}
                                        placeholder="Type your answer here..."
                                        className="w-full h-48 bg-slate-50 border-2 border-transparent focus:border-indigo-500/20 focus:bg-white rounded-2xl px-6 py-4 outline-none transition-all font-medium text-slate-700 resize-none text-sm leading-relaxed"
                                    />
                                )}
                            </div>
                        </div>

                        {/* Footer */}
                        {!selectedAssignment.hasSubmitted && (
                            <div className="p-6 border-t border-slate-100 bg-slate-50 flex justify-end gap-4">
                                <button onClick={() => setSelectedAssignment(null)} className="px-6 py-3 font-bold text-slate-500 hover:text-slate-800 transition-colors uppercase tracking-wider text-xs">
                                    Cancel
                                </button>
                                <button 
                                    onClick={handleSubmit} 
                                    disabled={!submissionText.trim() || isSubmitting}
                                    className="px-8 py-3 bg-indigo-600 text-white rounded-xl font-black uppercase tracking-widest text-xs shadow-xl shadow-indigo-600/20 hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-2"
                                >
                                    {isSubmitting ? "Submitting..." : "Submit Answer"}
                                    {!isSubmitting && <Send className="w-4 h-4 ml-1" />}
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
