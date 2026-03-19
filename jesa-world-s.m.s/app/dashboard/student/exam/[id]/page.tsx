"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { 
    Clock, 
    ArrowLeft, 
    CheckCircle2, 
    AlertCircle, 
    Loader2, 
    ChevronRight, 
    ChevronLeft 
} from "lucide-react";
import 'react-quill-new/dist/quill.snow.css';

export default function StudentExamPage() {
    const params = useParams();
    const router = useRouter();
    const [examId, setExamId] = useState<string>("");
    
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [exam, setExam] = useState<any>(null);
    const [questions, setQuestions] = useState<any[]>([]);
    
    const [currentIndex, setCurrentIndex] = useState(0);
    const [answers, setAnswers] = useState<Record<string, string>>({});
    
    // Exam Phases & Modals
    const [examPhase, setExamPhase] = useState<'OBJECTIVE' | 'THEORY'>('OBJECTIVE');
    const [showSubmitModal, setShowSubmitModal] = useState(false);
    const [showPhaseModal, setShowPhaseModal] = useState(false);
    
    // Timer
    const [timeLeft, setTimeLeft] = useState<number | null>(null);
    const [submitting, setSubmitting] = useState(false);
    const [result, setResult] = useState<any>(null);

    useEffect(() => {
        if (params.id) {
            setExamId(params.id as string);
        }
    }, [params]);

    useEffect(() => {
        if (!examId) return;
        fetchExamData();
    }, [examId]);

    useEffect(() => {
        // Countdown logic
        if (timeLeft === null || timeLeft <= 0 || result || submitting) return;
        
        const timerId = setInterval(() => {
            setTimeLeft(prev => {
                if (prev !== null && prev <= 1) {
                    clearInterval(timerId);
                    handleSubmitExam(true); // Auto-submit when time is up
                    return 0;
                }
                return prev ? prev - 1 : 0;
            });
        }, 1000);
        
        return () => clearInterval(timerId);
    }, [timeLeft, result, submitting]);

    const fetchExamData = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/student/exams/${examId}/questions`, {
                headers: { Authorization: `Bearer ${token}` }
            });

            if (!res.ok) {
                const data = await res.json();
                setError(data.error || "Failed to load exam. You may have already taken this exam.");
                setLoading(false);
                return;
            }

            const data = await res.json();
            setExam(data.exam);
            setQuestions(data.questions);
            if (data.questions.length > 0 && !data.questions.some((q: any) => q.type === 'MCQ')) {
                setExamPhase('THEORY');
            }
            
            // Parse duration (e.g. "1hr", "45 mins", "120")
            let mins = 60; // default 1 hr
            if (data.exam.duration) {
                const durStr = data.exam.duration.toString().toLowerCase();
                if (durStr.includes('hr') || durStr.includes('hour')) {
                    const val = parseFloat(durStr);
                    if (!isNaN(val)) mins = val * 60;
                } else {
                    const val = parseInt(durStr);
                    if (!isNaN(val)) mins = val;
                }
            }
            setTimeLeft(mins * 60); // convert to seconds
            
        } catch (err) {
            console.error(err);
            setError("A network error occurred.");
        }
        setLoading(false);
    };

    const handleAnswerSelect = (qId: string, value: string) => {
        setAnswers(prev => ({
            ...prev,
            [qId]: value
        }));
    };

    const handleSubmitExam = useCallback(async (autoSubmit = true) => {
        setSubmitting(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/student/exams/${examId}/submit`, {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}` 
                },
                body: JSON.stringify({ answers })
            });

            const data = await res.json();
            if (res.ok) {
                setResult(data);
            } else {
                setError(data.error || "Failed to submit exam.");
            }
        } catch (err) {
            setError("Error submitting exam. Please check your connection and try again.");
        }
        setSubmitting(false);
    }, [examId, answers]);


    // Render loading state
    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center min-h-screen bg-[#f1f3f6]">
                <Loader2 className="w-12 h-12 text-indigo-500 animate-spin mb-4" />
                <h2 className="text-slate-500 font-bold uppercase tracking-widest text-sm">Loading Exam Environment...</h2>
            </div>
        );
    }

    // Render error state
    if (error) {
        return (
            <div className="flex flex-col items-center justify-center min-h-screen bg-[#f1f3f6] p-6">
                <div className="bg-white p-10 rounded-[2.5rem] shadow-xl text-center max-w-md w-full">
                    <AlertCircle className="w-16 h-16 text-rose-500 mx-auto mb-6" />
                    <h2 className="text-2xl font-black text-slate-800 mb-2">Access Denied</h2>
                    <p className="text-slate-500 font-medium mb-8">{error}</p>
                    <button 
                        onClick={() => router.push("/dashboard/student")}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-4 px-8 rounded-2xl transition-all w-full"
                    >
                        Back to Dashboard
                    </button>
                </div>
            </div>
        );
    }

    // Render results view (after submission)
    if (result) {
        const percentage = Math.round((result.score / result.maxScore) * 100) || 0;
        let pColor = "text-emerald-500";
        if (percentage < 40) pColor = "text-rose-500";
        else if (percentage < 60) pColor = "text-amber-500";

        return (
            <div className="flex flex-col items-center justify-center min-h-screen bg-[#f1f3f6] p-6">
                <div className="bg-white p-10 rounded-[2.5rem] shadow-xl text-center max-w-lg w-full relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-32 bg-indigo-50 rounded-t-[2.5rem] -z-0" />
                    
                    <div className="relative z-10">
                        <div className="w-24 h-24 bg-white shadow-xl shadow-indigo-500/10 rounded-full flex items-center justify-center mx-auto mb-6 border-4 border-indigo-50">
                            <CheckCircle2 className="w-12 h-12 text-emerald-500" />
                        </div>
                        <h2 className="text-3xl font-black text-slate-900 mb-2">Exam Submitted!</h2>
                        <p className="text-slate-500 font-medium mb-8">Your {exam?.subject} examination has been successfully recorded.</p>
                        
                        <div className="bg-slate-50 border border-slate-100 rounded-3xl p-8 mb-8">
                            <h3 className="text-xs font-black text-slate-400 uppercase tracking-widest mb-4">Final Score (MCQ)</h3>
                            <div className="flex items-end justify-center gap-2 mb-2">
                                <span className="text-6xl font-black text-slate-900">{result.score}</span>
                                <span className="text-2xl font-bold text-slate-300 mb-1.5">/ {result.maxScore}</span>
                            </div>
                            <div className={`text-xl font-black ${pColor}`}>{percentage}% Match</div>
                        </div>

                        <button 
                            onClick={() => router.push("/dashboard/student")}
                            className="bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-4 px-8 rounded-2xl transition-all w-full shadow-lg shadow-indigo-500/20"
                        >
                            Return to Dashboard
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    if (!questions || questions.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center min-h-screen bg-[#f1f3f6] p-6">
                <div className="bg-white p-10 rounded-[2.5rem] shadow-xl text-center max-w-md w-full">
                    <AlertCircle className="w-16 h-16 text-amber-500 mx-auto mb-6" />
                    <h2 className="text-2xl font-black text-slate-800 mb-2">No Questions</h2>
                    <p className="text-slate-500 font-medium mb-8">This exam currently has no questions assigned to it. Please contact your teacher.</p>
                    <button onClick={() => router.push("/dashboard/student")} className="bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold py-4 px-8 rounded-2xl transition-all w-full">Go Back</button>
                </div>
            </div>
        );
    }

    // Exam Player UI
    const mcqQuestions = questions.filter(q => q.type === 'MCQ');
    const theoryQuestions = questions.filter(q => q.type === 'THEORY');
    const currentQuestions = examPhase === 'OBJECTIVE' ? mcqQuestions : theoryQuestions;
    
    if (!currentQuestions || currentQuestions.length === 0) return null;

    const q = currentQuestions[currentIndex];
    const isFirst = currentIndex === 0;
    const isLast = currentIndex === currentQuestions.length - 1;
    const answeredCount = currentQuestions.filter(q => answers[q.id]).length;

    // Time formatting
    const formatTime = (secs: number) => {
        const h = Math.floor(secs / 3600);
        const m = Math.floor((secs % 3600) / 60);
        const s = secs % 60;
        if (h > 0) return `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
        return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    };

    return (
        <div className="min-h-screen bg-[#f1f3f6] text-slate-900 font-sans flex flex-col">
            {/* Header */}
            <header className="bg-white h-20 shadow-sm flex items-center justify-between px-8 sticky top-0 z-50">
                <div className="flex items-center gap-4">
                    <button onClick={() => router.push("/dashboard/student")} className="w-10 h-10 rounded-xl bg-slate-100 hover:bg-slate-200 flex items-center justify-center transition-colors">
                        <ArrowLeft className="w-5 h-5 text-slate-600" />
                    </button>
                    <div>
                        <h1 className="text-lg font-black text-slate-800">{exam?.subject}</h1>
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{exam?.type} • {exam?.class}</p>
                    </div>
                </div>

                <div className="flex items-center gap-6">
                    <div className="hidden md:flex flex-col items-end mr-4">
                        <span className="text-[10px] font-black uppercase text-slate-400 tracking-widest">{examPhase === 'OBJECTIVE' ? 'Objective' : 'Theory'} Progress</span>
                        <div className="flex items-center gap-2 mt-1">
                            <div className="w-32 h-2 bg-slate-100 rounded-full overflow-hidden">
                                <div 
                                    className="h-full bg-indigo-500 transition-all duration-300"
                                    style={{ width: `${(answeredCount / currentQuestions.length) * 100}%` }}
                                />
                            </div>
                            <span className="text-xs font-bold text-slate-600">{answeredCount}/{currentQuestions.length}</span>
                        </div>
                    </div>
                    
                    <div className={`flex items-center gap-3 px-5 py-2.5 rounded-2xl font-bold ${
                        timeLeft && timeLeft < 300 ? 'bg-rose-50 text-rose-600' : 'bg-slate-100 text-slate-700'
                    }`}>
                        <Clock className={`w-5 h-5 ${timeLeft && timeLeft < 300 ? 'animate-pulse' : ''}`} />
                        <span className="font-black text-lg tracking-tight font-mono">{timeLeft !== null ? formatTime(timeLeft) : "--:--"}</span>
                    </div>

                    <button 
                        onClick={() => setShowSubmitModal(true)}
                        disabled={submitting}
                        className="bg-emerald-500 hover:bg-emerald-600 text-white font-bold py-2.5 px-6 rounded-2xl shadow-lg shadow-emerald-500/20 transition-all focus:ring-4 focus:ring-emerald-500/30 flex items-center gap-2 disabled:opacity-50"
                    >
                        {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
                        Submit
                    </button>
                </div>
            </header>

            {/* Main Content View */}
            <main className="flex-1 max-w-4xl mx-auto w-full p-6 md:p-8 flex flex-col relative z-10 overflow-hidden">
                <div className="flex-1 bg-white rounded-[2.5rem] p-8 md:p-12 shadow-xl shadow-slate-200/50 border border-white flex flex-col overflow-y-auto scrollbar-hide">
                    
                    <div className="flex items-center justify-between mb-8 pb-6 border-b border-slate-100">
                        <span className="px-4 py-1.5 bg-indigo-50 text-indigo-600 font-bold uppercase tracking-widest text-xs rounded-full">
                            Question {currentIndex + 1} of {currentQuestions.length}
                        </span>
                        <span className="text-sm font-bold text-slate-400">
                            {q.marks || 1} mark{q.marks > 1 ? 's' : ''}
                        </span>
                    </div>

                    <div 
                        className="text-2xl font-medium leading-relaxed text-slate-800 mb-10 prose prose-slate max-w-none"
                        dangerouslySetInnerHTML={{ __html: q.question }} 
                    />

                    <div className="flex-1">
                        {q.type === 'MCQ' && Array.isArray(q.options) && q.options.length > 0 ? (
                            <div className="grid gap-4">
                                {q.options.map((opt: string, i: number) => {
                                    if (!opt) return null;
                                    const isSelected = answers[q.id] === opt;
                                    const letter = String.fromCharCode(65 + i);

                                    return (
                                        <button
                                            key={i}
                                            onClick={() => handleAnswerSelect(q.id, opt)}
                                            className={`flex items-start text-left p-6 rounded-2xl transition-all border-2 ${
                                                isSelected 
                                                ? 'bg-indigo-50 border-indigo-500 shadow-lg shadow-indigo-500/10' 
                                                : 'bg-white border-slate-100 hover:border-slate-300 hover:bg-slate-50'
                                            }`}
                                        >
                                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-black flex-shrink-0 mr-4 ${
                                                isSelected ? 'bg-indigo-500 text-white' : 'bg-slate-100 text-slate-500'
                                            }`}>
                                                {letter}
                                            </div>
                                            <span 
                                                className={`text-lg pt-0.5 ${isSelected ? 'font-bold text-indigo-900' : 'text-slate-700 font-medium'}`}
                                                dangerouslySetInnerHTML={{ __html: opt }}
                                            />
                                        </button>
                                    );
                                })}
                            </div>
                        ) : (
                            <div className="h-full">
                                <textarea 
                                    value={answers[q.id] || ""}
                                    onChange={(e) => handleAnswerSelect(q.id, e.target.value)}
                                    placeholder="Type your detailed answer here..."
                                    className="w-full h-64 p-6 bg-slate-50 border-2 border-slate-100 focus:border-indigo-500 rounded-3xl outline-none resize-none font-medium text-slate-800 text-lg transition-colors"
                                />
                            </div>
                        )}
                    </div>
                </div>

                {/* Footer Navigation */}
                <div className="mt-8 flex items-center justify-between">
                    <button 
                        onClick={() => setCurrentIndex(prev => prev - 1)}
                        disabled={isFirst}
                        className="flex items-center gap-2 bg-white text-slate-700 font-bold py-4 px-6 rounded-2xl shadow hover:shadow-md transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <ChevronLeft className="w-5 h-5" /> Previous
                    </button>
                    
                    {/* Tiny Pagination Dots */}
                    <div className="hidden md:flex gap-1.5 overflow-x-auto max-w-[40%] scrollbar-hide">
                        {currentQuestions.map((_, i) => (
                            <button
                                key={i}
                                onClick={() => setCurrentIndex(i)}
                                className={`flex-shrink-0 w-3 h-3 rounded-full transition-all ${
                                    i === currentIndex ? 'bg-indigo-600 scale-125' : 
                                    answers[currentQuestions[i].id] ? 'bg-emerald-400' : 'bg-slate-300 hover:bg-slate-400'
                                }`}
                                aria-label={`Go to question ${i + 1}`}
                            />
                        ))}
                    </div>

                    {isLast && examPhase === 'OBJECTIVE' && theoryQuestions.length > 0 ? (
                        <button 
                            onClick={() => setShowPhaseModal(true)}
                            className="flex items-center gap-2 bg-indigo-600 text-white font-bold py-4 px-6 rounded-2xl shadow-lg shadow-indigo-500/20 hover:bg-indigo-700 transition-all"
                        >
                            Proceed to Theory <ChevronRight className="w-5 h-5" />
                        </button>
                    ) : (
                        <button 
                            onClick={() => setCurrentIndex(prev => prev + 1)}
                            disabled={isLast}
                            className="flex items-center gap-2 bg-indigo-600 text-white font-bold py-4 px-6 rounded-2xl shadow-lg shadow-indigo-500/20 hover:bg-indigo-700 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                            Next <ChevronRight className="w-5 h-5" />
                        </button>
                    )}
                </div>
            </main>

            {/* Custom Modals */}
            {showSubmitModal && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4">
                    <div className="bg-white rounded-[2.5rem] p-10 max-w-md w-full shadow-2xl text-center">
                        <AlertCircle className="w-16 h-16 text-indigo-500 mx-auto mb-6" />
                        <h3 className="text-3xl font-black text-slate-800 mb-2">Submit Exam?</h3>
                        <p className="text-slate-500 font-medium mb-8 text-lg">Are you sure you're ready to submit? You won't be able to change your answers.</p>
                        <div className="flex gap-4">
                            <button onClick={() => setShowSubmitModal(false)} className="flex-1 py-4 rounded-2xl font-bold bg-slate-100 text-slate-700 hover:bg-slate-200 transition-colors">Cancel</button>
                            <button onClick={() => { setShowSubmitModal(false); handleSubmitExam(true); }} className="flex-1 py-4 rounded-2xl font-bold bg-emerald-500 text-white hover:bg-emerald-600 shadow-lg shadow-emerald-500/20 transition-colors">Confirm Submit</button>
                        </div>
                    </div>
                </div>
            )}

            {showPhaseModal && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4">
                    <div className="bg-white rounded-[2.5rem] p-10 max-w-md w-full shadow-2xl text-center">
                        <div className="w-16 h-16 bg-indigo-50 rounded-2xl flex items-center justify-center mx-auto mb-6">
                            <ChevronRight className="w-8 h-8 text-indigo-500" />
                        </div>
                        <h3 className="text-2xl font-black text-slate-800 mb-2">Move to Theory?</h3>
                        <p className="text-slate-500 font-medium mb-8">You are about to start the Theory Section. You <strong>cannot return</strong> to the Objective section once you proceed.</p>
                        <div className="flex gap-4">
                            <button onClick={() => setShowPhaseModal(false)} className="flex-1 py-4 rounded-2xl font-bold bg-slate-100 text-slate-700 hover:bg-slate-200 transition-colors">Go Back</button>
                            <button onClick={() => { 
                                setExamPhase('THEORY'); 
                                setCurrentIndex(0); 
                                setShowPhaseModal(false); 
                            }} className="flex-1 py-4 rounded-2xl font-bold bg-indigo-600 text-white hover:bg-indigo-700 shadow-lg shadow-indigo-500/20 transition-colors">Proceed</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
