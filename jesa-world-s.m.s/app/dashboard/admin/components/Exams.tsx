"use client";

import { useState, useEffect } from "react";
import toast from "react-hot-toast";
import {
    BookOpen,
    Calendar,
    Clipboard,
    Plus,
    Award,
    Search,
    Edit,
    Trash2,
    X,
    Loader2,
    CheckCircle2,
    FileQuestion,
    User,
    Eye,
    ChevronDown,
    ChevronUp
} from "lucide-react";

export default function Exams() {
    const [activeTab, setActiveTab] = useState<'SCHEDULE' | 'RESULTS' | 'GRADING'>('SCHEDULE');

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Navigation Tabs */}
            <div className="flex items-center space-x-1 bg-white p-1.5 rounded-2xl border border-slate-200 w-fit shadow-sm">
                <button
                    onClick={() => setActiveTab('SCHEDULE')}
                    className={`px-6 py-2 rounded-xl text-sm font-bold transition-all ${activeTab === 'SCHEDULE' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20' : 'text-slate-500 hover:bg-slate-50'}`}
                >
                    Exam Schedule
                </button>
                <button
                    onClick={() => setActiveTab('RESULTS')}
                    className={`px-6 py-2 rounded-xl text-sm font-bold transition-all ${activeTab === 'RESULTS' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20' : 'text-slate-500 hover:bg-slate-50'}`}
                >
                    Results Entry
                </button>
                <button
                    onClick={() => setActiveTab('GRADING')}
                    className={`px-6 py-2 rounded-xl text-sm font-bold transition-all ${activeTab === 'GRADING' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20' : 'text-slate-500 hover:bg-slate-50'}`}
                >
                    Grading System
                </button>
            </div>

            {/* Content based on tab */}
            {activeTab === 'SCHEDULE' && <ExamScheduleView />}
            {activeTab === 'RESULTS' && <ResultsEntryView />}
            {activeTab === 'GRADING' && <GradingSystemView />}
        </div>
    );
}

function ExamScheduleView() {
    const [exams, setExams] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [editingExam, setEditingExam] = useState<any>(null);
    const [availableSubjects, setAvailableSubjects] = useState<any[]>([]);
    const [readiness, setReadiness] = useState<any[]>([]);
    const [readinessLoading, setReadinessLoading] = useState(true);
    const [viewingQuestions, setViewingQuestions] = useState<{ subject: string; class: string } | null>(null);
    const [questions, setQuestions] = useState<any[]>([]);
    const [questionsLoading, setQuestionsLoading] = useState(false);
    const [questionTab, setQuestionTab] = useState<'MCQ' | 'THEORY'>('MCQ');
    const [expandedQuestion, setExpandedQuestion] = useState<string | null>(null);

    const [form, setForm] = useState({
        subject: "",
        class: "Junior Secondary",
        date: "",
        time: "",
        duration: "",
        type: "First Term"
    });

    const fetchExams = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/exams`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = await res.json();
            if (res.ok) setExams(data);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const fetchSubjects = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/subjects`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = await res.json();
            if (res.ok) setAvailableSubjects(data);
        } catch (err) {
            console.error(err);
        }
    };

    const fetchReadiness = async () => {
        setReadinessLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/exams/question-readiness`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setReadiness(data);
            }
        } catch (err) {
            console.error(err);
        } finally {
            setReadinessLoading(false);
        }
    };

    const openQuestionViewer = async (subject: string, cls: string) => {
        setViewingQuestions({ subject, class: cls });
        setQuestionTab('MCQ');
        setExpandedQuestion(null);
        setQuestionsLoading(true);
        try {
            const token = localStorage.getItem("token");
            const url = new URL(`${process.env.NEXT_PUBLIC_API_URL}/teacher/exams/questions`);
            url.searchParams.set('subject', subject);
            url.searchParams.set('class', cls);
            const res = await fetch(url.toString(), {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                setQuestions(await res.json());
            }
        } catch (err) {
            console.error(err);
        } finally {
            setQuestionsLoading(false);
        }
    };

    useEffect(() => {
        fetchExams();
        fetchSubjects();
        fetchReadiness();
    }, []);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const url = editingExam
                ? `${process.env.NEXT_PUBLIC_API_URL}/admin/exams/${editingExam.id}`
                : `${process.env.NEXT_PUBLIC_API_URL}/admin/exams`;

            const res = await fetch(url, {
                method: editingExam ? "PUT" : "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(form)
            });

            if (res.ok) {
                toast.success(`Exam schedule ${editingExam ? 'updated' : 'created'} successfully!`);
                fetchExams();
                setShowModal(false);
                setEditingExam(null);
                setForm({ subject: "", class: "Junior Secondary", date: "", time: "", duration: "", type: "First Term" });
            } else {
                const data = await res.json();
                toast.error(data.details || data.error || "Action failed");
            }
        } catch (err) {
            toast.error("Network error");
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm("Are you sure you want to delete this exam schedule?")) return;
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/exams/${id}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                toast.success("Schedule deleted");
                fetchExams();
            }
        } catch (err) {
            toast.error("Delete failed");
        } finally {
            setLoading(false);
        }
    };

    const handleEdit = (exam: any) => {
        setEditingExam(exam);
        setForm({
            subject: exam.subject,
            class: exam.class,
            date: exam.date,
            time: exam.time,
            duration: exam.duration,
            type: exam.type
        });
        setShowModal(true);
    };

    return (
        <div className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm relative">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h2 className="text-xl font-black text-slate-900">Active Exam Schedules</h2>
                    <p className="text-sm text-slate-500 font-medium">Manage and view upcoming examinations.</p>
                </div>
                <button
                    onClick={() => {
                        setEditingExam(null);
                        setForm({ subject: "", class: "Junior Secondary", date: "", time: "", duration: "", type: "First Term" });
                        setShowModal(true);
                    }}
                    className="flex items-center space-x-2 bg-indigo-600 text-white py-2.5 px-6 rounded-xl text-sm font-bold hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-600/20"
                >
                    <Plus className="w-4 h-4" />
                    <span>Create Schedule</span>
                </button>
            </div>

            {loading && exams.length === 0 ? (
                <div className="flex flex-col items-center justify-center p-20 text-slate-400">
                    <Loader2 className="w-8 h-8 animate-spin mb-4" />
                    <p className="font-bold">Loading schedules...</p>
                </div>
            ) : exams.length === 0 ? (
                <div className="text-center p-20 border-2 border-dashed border-slate-100 rounded-[2rem]">
                    <Search className="w-12 h-12 text-slate-200 mx-auto mb-4" />
                    <p className="text-slate-400 font-bold">No exam schedules found. Click &quot;Create Schedule&quot; to get started.</p>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {exams.map(exam => (
                        <div key={exam.id} className="p-6 bg-slate-50 border border-slate-100 rounded-3xl group hover:border-indigo-200 hover:bg-white transition-all relative">
                            <div className="flex items-center justify-between mb-4">
                                <div className="p-3 bg-white rounded-2xl shadow-sm">
                                    <BookOpen className="w-5 h-5 text-indigo-600" />
                                </div>
                                <div className="flex items-center space-x-2">
                                    <button onClick={() => handleEdit(exam)} className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors">
                                        <Edit className="w-4 h-4" />
                                    </button>
                                    <button onClick={() => handleDelete(exam.id)} className="p-2 text-slate-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors">
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                            <h3 className="text-lg font-black text-slate-900 mb-1">{exam.subject}</h3>
                            <div className="flex items-center space-x-2 mb-6">
                                <span className="text-[10px] bg-indigo-50 text-indigo-700 px-3 py-1 rounded-full font-black uppercase tracking-wider">{exam.class}</span>
                                <span className="text-[10px] bg-slate-200 text-slate-600 px-3 py-1 rounded-full font-black uppercase tracking-wider">{exam.type}</span>
                            </div>

                            <div className="space-y-3">
                                <div className="flex items-center text-sm font-bold text-slate-600">
                                    <Calendar className="w-4 h-4 mr-3 text-slate-400" />
                                    {new Date(exam.date).toLocaleDateString()}
                                </div>
                                <div className="flex items-center text-sm font-bold text-slate-600">
                                    <Clipboard className="w-4 h-4 mr-3 text-slate-400" />
                                    {exam.time} ({exam.duration})
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Question Readiness Panel */}
            <div className="mt-10 pt-8 border-t border-slate-100">
                <div className="flex items-center justify-between mb-6">
                    <div>
                        <h3 className="text-lg font-black text-slate-900">Question Readiness</h3>
                        <p className="text-sm text-slate-500 font-medium mt-0.5">Subjects with exam questions already set by teachers</p>
                    </div>
                    <button
                        onClick={fetchReadiness}
                        className="text-xs font-bold text-indigo-600 hover:underline"
                    >
                        Refresh
                    </button>
                </div>

                {readinessLoading ? (
                    <div className="flex items-center justify-center py-12">
                        <Loader2 className="w-6 h-6 text-indigo-500 animate-spin" />
                    </div>
                ) : readiness.length === 0 ? (
                    <div className="text-center py-12 border-2 border-dashed border-slate-100 rounded-[2rem]">
                        <FileQuestion className="w-10 h-10 text-slate-200 mx-auto mb-3" />
                        <p className="text-slate-400 font-bold text-sm">No teacher has set questions yet.</p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                        {readiness.sort((a: any, b: any) => a.subject.localeCompare(b.subject)).map((item: any, idx: number) => (
                            <div key={idx} className="p-5 bg-emerald-50/60 border border-emerald-100 rounded-2xl flex flex-col gap-3 cursor-pointer hover:shadow-md hover:border-emerald-300 transition-all group" onClick={() => openQuestionViewer(item.subject, item.class)}>
                                <div className="flex items-start justify-between">
                                    <div>
                                        <p className="font-black text-slate-800 text-sm">{item.subject}</p>
                                        <span className="text-[10px] font-black text-indigo-600 uppercase tracking-wider bg-indigo-50 px-2 py-0.5 rounded-md">{item.class}</span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <div className="flex items-center gap-1.5 bg-emerald-100 text-emerald-700 px-3 py-1.5 rounded-xl flex-shrink-0">
                                            <CheckCircle2 className="w-4 h-4" />
                                            <span className="text-xs font-black">{item.totalQuestions} Qs</span>
                                        </div>
                                        <div className="p-1.5 bg-white rounded-lg opacity-0 group-hover:opacity-100 transition-opacity">
                                            <Eye className="w-4 h-4 text-indigo-500" />
                                        </div>
                                    </div>
                                </div>
                                <div className="space-y-1 border-t border-emerald-100 pt-3">
                                    {item.teachers.map((t: any, ti: number) => (
                                        <div key={ti} className="flex items-center justify-between text-xs font-bold">
                                            <div className="flex items-center gap-2 text-slate-600">
                                                <User className="w-3.5 h-3.5 text-slate-400" />
                                                <span>{t.name}</span>
                                            </div>
                                            <span className="text-emerald-600">{t.count} Qs</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Question Viewer Modal */}
            {viewingQuestions && (
                <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-10 bg-black/60 backdrop-blur-sm overflow-y-auto">
                    <div className="w-full max-w-3xl bg-white rounded-[2rem] border border-slate-200 shadow-2xl animate-in zoom-in-95 duration-200">
                        {/* Modal Header */}
                        <div className="flex items-start justify-between p-8 pb-0">
                            <div>
                                <h2 className="text-2xl font-black text-slate-900">{viewingQuestions.subject}</h2>
                                <span className="text-xs font-black text-indigo-600 uppercase tracking-wider bg-indigo-50 px-3 py-1 rounded-full">{viewingQuestions.class}</span>
                            </div>
                            <button
                                onClick={() => { setViewingQuestions(null); setQuestions([]); }}
                                className="p-2.5 bg-slate-100 hover:bg-slate-200 rounded-xl transition-colors"
                            >
                                <X className="w-5 h-5 text-slate-600" />
                            </button>
                        </div>

                        {/* Tabs */}
                        <div className="flex items-center gap-2 px-8 pt-6 pb-0">
                            {(['MCQ', 'THEORY'] as const).map(tab => {
                                const count = questions.filter(q => q.type === tab).length;
                                return (
                                    <button
                                        key={tab}
                                        onClick={() => { setQuestionTab(tab); setExpandedQuestion(null); }}
                                        className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-black transition-all ${
                                            questionTab === tab
                                                ? tab === 'MCQ' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20' : 'bg-amber-500 text-white shadow-lg shadow-amber-500/20'
                                                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                                        }`}
                                    >
                                        <span>{tab === 'MCQ' ? 'Objective (MCQ)' : 'Theory'}</span>
                                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-black ${
                                            questionTab === tab ? 'bg-white/25 text-white' : 'bg-slate-200 text-slate-600'
                                        }`}>{count}</span>
                                    </button>
                                );
                            })}
                        </div>

                        {/* Content */}
                        <div className="p-8 pt-6 space-y-4 max-h-[60vh] overflow-y-auto">
                            {questionsLoading ? (
                                <div className="flex items-center justify-center py-16">
                                    <Loader2 className="w-7 h-7 animate-spin text-indigo-500" />
                                </div>
                            ) : questions.filter(q => q.type === questionTab).length === 0 ? (
                                <div className="text-center py-16 border-2 border-dashed border-slate-100 rounded-2xl">
                                    <FileQuestion className="w-10 h-10 text-slate-200 mx-auto mb-3" />
                                    <p className="text-slate-400 font-bold text-sm">No {questionTab === 'MCQ' ? 'objective' : 'theory'} questions set for this subject.</p>
                                </div>
                            ) : (
                                questions
                                    .filter(q => q.type === questionTab)
                                    .map((q: any, idx: number) => (
                                        <div
                                            key={q.id}
                                            className={`border rounded-2xl overflow-hidden transition-all ${
                                                questionTab === 'MCQ' ? 'border-indigo-100' : 'border-amber-100'
                                            }`}
                                        >
                                            {/* Question header */}
                                            <button
                                                className="w-full flex items-start gap-4 p-5 text-left hover:bg-slate-50 transition-colors"
                                                onClick={() => setExpandedQuestion(expandedQuestion === q.id ? null : q.id)}
                                            >
                                                <span className={`flex-shrink-0 w-7 h-7 rounded-lg flex items-center justify-center text-xs font-black ${
                                                    questionTab === 'MCQ' ? 'bg-indigo-100 text-indigo-700' : 'bg-amber-100 text-amber-700'
                                                }`}>{idx + 1}</span>
                                                <p className="flex-1 text-sm font-bold text-slate-800 leading-relaxed" dangerouslySetInnerHTML={{ __html: q.question }} />
                                                <span className="flex-shrink-0">
                                                    {expandedQuestion === q.id
                                                        ? <ChevronUp className="w-4 h-4 text-slate-400" />
                                                        : <ChevronDown className="w-4 h-4 text-slate-400" />}
                                                </span>
                                            </button>

                                            {/* Expanded: options + answer */}
                                            {expandedQuestion === q.id && (
                                                <div className="px-5 pb-5 pt-0 border-t border-slate-100 bg-slate-50/50">
                                                    {questionTab === 'MCQ' && q.options && Array.isArray(q.options) && (
                                                        <div className="mt-4 space-y-2">
                                                            {q.options.map((opt: string, oi: number) => {
                                                                const letter = String.fromCharCode(65 + oi);
                                                                const isCorrect = opt === q.answer || letter === q.answer;
                                                                return (
                                                                    <div
                                                                        key={oi}
                                                                        className={`flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-bold ${
                                                                            isCorrect ? 'bg-emerald-100 text-emerald-800 ring-1 ring-emerald-300' : 'bg-white text-slate-700 border border-slate-200'
                                                                        }`}
                                                                    >
                                                                        <span className={`w-6 h-6 rounded-lg flex items-center justify-center text-xs font-black flex-shrink-0 ${
                                                                            isCorrect ? 'bg-emerald-400 text-white' : 'bg-slate-100 text-slate-500'
                                                                        }`}>{letter}</span>
                                                                        <span dangerouslySetInnerHTML={{ __html: opt }} />
                                                                        {isCorrect && <span className="ml-auto text-[10px] font-black text-emerald-600 uppercase tracking-wider">✓ Correct</span>}
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                    )}
                                                    {questionTab === 'THEORY' && (
                                                        <div className="mt-4">
                                                            <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Model Answer</p>
                                                            <div className="p-4 bg-emerald-50 border border-emerald-100 rounded-xl text-sm text-emerald-800 font-medium leading-relaxed" dangerouslySetInnerHTML={{ __html: q.answer || '<em>No answer provided</em>' }} />
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    ))
                            )}
                        </div>

                        <div className="px-8 pb-6 flex items-center justify-between border-t border-slate-100 pt-4">
                            <p className="text-xs font-bold text-slate-400">
                                {questions.filter(q => q.type === questionTab).length} {questionTab === 'MCQ' ? 'objective' : 'theory'} question{questions.filter(q => q.type === questionTab).length !== 1 ? 's' : ''}
                            </p>
                            <button
                                onClick={() => { setViewingQuestions(null); setQuestions([]); }}
                                className="px-6 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-black text-sm rounded-xl transition-colors"
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Modal */}
            {showModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                    <div className="w-full max-w-lg bg-white rounded-3xl border border-slate-200 p-8 shadow-2xl animate-in zoom-in duration-300">
                        <div className="flex justify-between items-center mb-6">
                            <h2 className="text-2xl font-black text-slate-900">{editingExam ? 'Edit' : 'Create'} Exam Schedule</h2>
                            <button onClick={() => setShowModal(false)} className="text-slate-400 hover:text-slate-600"><X /></button>
                        </div>
                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div className="space-y-2">
                                <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Subject</label>
                                <select
                                    required
                                    value={form.subject}
                                    onChange={e => setForm({ ...form, subject: e.target.value })}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                >
                                    <option value="">Select a Subject</option>
                                    {['JUNIOR', 'SENIOR'].map(section => (
                                        <optgroup key={section} label={section}>
                                            {availableSubjects
                                                .filter((s: any) => s.section === section)
                                                .map((s: any) => (
                                                    <option key={s.id} value={s.name}>{s.name}</option>
                                                ))
                                            }
                                        </optgroup>
                                    ))}
                                </select>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Class</label>
                                    <select
                                        value={form.class}
                                        onChange={e => setForm({ ...form, class: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    >
                                        <option value="Junior Secondary">Junior Secondary</option>
                                        <option value="Senior Secondary">Senior Secondary</option>
                                    </select>
                                </div>
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Exam Type</label>
                                    <select
                                        value={form.type}
                                        onChange={e => setForm({ ...form, type: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    >
                                        <option value="First Term">First Term</option>
                                        <option value="Second Term">Second Term</option>
                                        <option value="Third Term">Third Term</option>
                                        <option value="MOCK">MOCK</option>
                                        <option value="WAEC">WAEC</option>
                                        <option value="NECO">NECO</option>
                                    </select>
                                </div>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Date</label>
                                    <input
                                        required
                                        type="date"
                                        value={form.date}
                                        onChange={e => setForm({ ...form, date: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Time</label>
                                    <input
                                        required
                                        type="time"
                                        value={form.time}
                                        onChange={e => setForm({ ...form, time: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                            </div>
                            <div className="space-y-2">
                                <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Duration</label>
                                <input
                                    type="text"
                                    value={form.duration}
                                    onChange={e => setForm({ ...form, duration: e.target.value })}
                                    placeholder="e.g. 2 Hours"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full bg-indigo-600 text-white p-4 rounded-2xl font-black hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-600/20 flex items-center justify-center space-x-2"
                            >
                                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <span>{editingExam ? 'Update' : 'Create'} Schedule</span>}
                            </button>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}

function ResultsEntryView() {
    const [students, setStudents] = useState<any[]>([]);
    const [subjects, setSubjects] = useState<any[]>([]);
    const [loading, setLoading] = useState(false);

    const [form, setForm] = useState({
        studentId: "",
        subject: "",
        marks: "",
        term: "First Term",
        class: "js1"
    });

    useEffect(() => {
        const fetchData = async () => {
            try {
                const token = localStorage.getItem("token");
                const [studentsRes, subjectsRes] = await Promise.all([
                    fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users/STUDENT`, { headers: { Authorization: `Bearer ${token}` } }),
                    fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/subjects`, { headers: { Authorization: `Bearer ${token}` } })
                ]);

                if (studentsRes.ok) setStudents(await studentsRes.json());
                if (subjectsRes.ok) setSubjects(await subjectsRes.json());
            } catch (err) {
                console.error(err);
            }
        };
        fetchData();
    }, []);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!form.studentId || !form.subject || !form.marks) {
            toast.error("Please fill all required fields");
            return;
        }

        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/results`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(form)
            });

            if (res.ok) {
                toast.success("Result recorded successfully!");
                setForm({ ...form, marks: "" });
            } else {
                const data = await res.json();
                toast.error(data.error || "Failed to record result");
            }
        } catch (err) {
            toast.error("Network error");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm relative">
            <div className="mb-8">
                <h2 className="text-xl font-black text-slate-900">Record Student Marks</h2>
                <p className="text-sm text-slate-500 font-medium">Enter scores for individual students by subject and term.</p>
            </div>

            <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-2 gap-6 items-end">
                <div className="space-y-2">
                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Select Student</label>
                    <select
                        required
                        value={form.studentId}
                        onChange={e => {
                            const student = students.find((s: any) => s.id === e.target.value);
                            setForm({ ...form, studentId: e.target.value, class: student?.studentClass || form.class });
                        }}
                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                    >
                        <option value="">Choose Student</option>
                        {['js1', 'js2', 'js3', 'ss1', 'ss2', 'ss3'].map(cls => (
                            <optgroup key={cls} label={cls.toUpperCase()}>
                                {students
                                    .filter((s: any) => s.studentClass?.toLowerCase() === cls)
                                    .map((s: any) => (
                                        <option key={s.id} value={s.id}>{s.firstName} {s.lastName} ({s.studentId})</option>
                                    ))
                                }
                            </optgroup>
                        ))}
                    </select>
                </div>

                <div className="space-y-2">
                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Term</label>
                    <select
                        value={form.term}
                        onChange={e => setForm({ ...form, term: e.target.value })}
                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                    >
                        <option value="First Term">First Term</option>
                        <option value="Second Term">Second Term</option>
                        <option value="Third Term">Third Term</option>
                        <option value="MOCK">MOCK</option>
                    </select>
                </div>

                <div className="space-y-2">
                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Subject</label>
                    <select
                        required
                        value={form.subject}
                        onChange={e => setForm({ ...form, subject: e.target.value })}
                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                    >
                        <option value="">Select Subject</option>
                        {['JUNIOR', 'SENIOR'].map(sec => (
                            <optgroup key={sec} label={sec}>
                                {subjects.filter((s: any) => s.section === sec).map((s: any) => (
                                    <option key={s.id} value={s.name}>{s.name}</option>
                                ))}
                            </optgroup>
                        ))}
                    </select>
                </div>

                <div className="space-y-2">
                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Marks (Max 100)</label>
                    <div className="flex space-x-3">
                        <input
                            required
                            type="number"
                            step="0.1"
                            max="100"
                            min="0"
                            value={form.marks}
                            onChange={e => setForm({ ...form, marks: e.target.value })}
                            placeholder="Score"
                            className="flex-1 bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                        />
                        <button
                            type="submit"
                            disabled={loading}
                            className="bg-indigo-600 text-white px-8 py-3 rounded-xl font-black hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-600/20 flex items-center justify-center min-w-[140px]"
                        >
                            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Record"}
                        </button>
                    </div>
                </div>
            </form>

            <div className="mt-12 pt-8 border-t border-slate-100 italic text-slate-400 text-xs font-medium">
                Note: Grades are automatically calculated based on the configured grading scale for the school.
            </div>
        </div>
    );
}

function GradingSystemView() {
    const [grades, setGrades] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [editingGrade, setEditingGrade] = useState<any>(null);

    const [form, setForm] = useState({
        grade: "",
        minScore: "",
        maxScore: "",
        remark: ""
    });

    const fetchGrades = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/grading`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = await res.json();
            if (res.ok) setGrades(data);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchGrades();
    }, []);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const url = editingGrade
                ? `${process.env.NEXT_PUBLIC_API_URL}/admin/grading/${editingGrade.id}`
                : `${process.env.NEXT_PUBLIC_API_URL}/admin/grading`;

            const res = await fetch(url, {
                method: editingGrade ? "PUT" : "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(form)
            });

            if (res.ok) {
                toast.success(`Grade rule ${editingGrade ? 'updated' : 'added'} successfully!`);
                fetchGrades();
                setShowModal(false);
                setEditingGrade(null);
                setForm({ grade: "", minScore: "", maxScore: "", remark: "" });
            } else {
                const data = await res.json();
                toast.error(data.error || "Action failed");
            }
        } catch (err) {
            toast.error("Network error");
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm("Are you sure you want to delete this grading rule?")) return;
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/grading/${id}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                toast.success("Grade rule deleted");
                fetchGrades();
            }
        } catch (err) {
            toast.error("Delete failed");
        } finally {
            setLoading(false);
        }
    };

    const handleEdit = (grade: any) => {
        setEditingGrade(grade);
        setForm({
            grade: grade.grade,
            minScore: grade.minScore.toString(),
            maxScore: grade.maxScore.toString(),
            remark: grade.remark || ""
        });
        setShowModal(true);
    };

    return (
        <div className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm relative">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h2 className="text-xl font-black text-slate-900">Grading Scale Configuration</h2>
                    <p className="text-sm text-slate-500 font-medium">Define how marks are converted to grades.</p>
                </div>
                <button
                    onClick={() => {
                        setEditingGrade(null);
                        setForm({ grade: "", minScore: "", maxScore: "", remark: "" });
                        setShowModal(true);
                    }}
                    className="flex items-center space-x-2 bg-indigo-600 text-white py-2.5 px-6 rounded-xl text-sm font-bold hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-600/20"
                >
                    <Plus className="w-4 h-4" />
                    <span>Add Grade Rule</span>
                </button>
            </div>

            {loading && grades.length === 0 ? (
                <div className="flex flex-col items-center justify-center p-20 text-slate-400">
                    <Loader2 className="w-8 h-8 animate-spin mb-4" />
                    <p className="font-bold">Loading grading system...</p>
                </div>
            ) : grades.length === 0 ? (
                <div className="text-center p-20 border-2 border-dashed border-slate-100 rounded-[2rem]">
                    <Plus className="w-12 h-12 text-slate-200 mx-auto mb-4" />
                    <p className="text-slate-400 font-bold">No grading rules defined. Click &quot;Add Grade Rule&quot; to get started.</p>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {grades.map((g: any) => (
                        <div key={g.id} className="p-6 bg-slate-50 border border-slate-100 rounded-3xl group hover:border-indigo-200 hover:bg-white transition-all relative">
                            <div className="flex items-center justify-between mb-4">
                                <span className="text-2xl font-black text-indigo-600">{g.grade}</span>
                                <div className="flex items-center space-x-2">
                                    <button onClick={() => handleEdit(g)} className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors">
                                        <Edit className="w-4 h-4" />
                                    </button>
                                    <button onClick={() => handleDelete(g.id)} className="p-2 text-slate-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors">
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                            <div className="flex items-end justify-between">
                                <div>
                                    <p className="text-[10px] font-black text-slate-400 tracking-widest uppercase">{g.remark || 'REMARK'}</p>
                                    <h4 className="text-sm font-bold text-slate-900">{g.minScore} - {g.maxScore}%</h4>
                                </div>
                                <Award className="w-8 h-8 text-slate-100" />
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Modal */}
            {showModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                    <div className="w-full max-w-md bg-white rounded-3xl border border-slate-200 p-8 shadow-2xl animate-in zoom-in duration-300">
                        <div className="flex justify-between items-center mb-6">
                            <h2 className="text-2xl font-black text-slate-900">{editingGrade ? 'Edit' : 'Add'} Grade Rule</h2>
                            <button onClick={() => setShowModal(false)} className="text-slate-400 hover:text-slate-600"><X /></button>
                        </div>
                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div className="space-y-2">
                                <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Grade Symbol</label>
                                <input
                                    required
                                    type="text"
                                    value={form.grade}
                                    onChange={e => setForm({ ...form, grade: e.target.value })}
                                    placeholder="e.g. A1, B, C6"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                />
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Min Score</label>
                                    <input
                                        required
                                        type="number"
                                        value={form.minScore}
                                        onChange={e => setForm({ ...form, minScore: e.target.value })}
                                        placeholder="0"
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Max Score</label>
                                    <input
                                        required
                                        type="number"
                                        value={form.maxScore}
                                        onChange={e => setForm({ ...form, maxScore: e.target.value })}
                                        placeholder="100"
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                            </div>
                            <div className="space-y-2">
                                <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Remark</label>
                                <input
                                    type="text"
                                    value={form.remark}
                                    onChange={e => setForm({ ...form, remark: e.target.value })}
                                    placeholder="e.g. Excellent"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full bg-indigo-600 text-white p-4 rounded-2xl font-black hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-600/20 flex items-center justify-center space-x-2"
                            >
                                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <span>{editingGrade ? 'Update' : 'Add'} Rule</span>}
                            </button>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
