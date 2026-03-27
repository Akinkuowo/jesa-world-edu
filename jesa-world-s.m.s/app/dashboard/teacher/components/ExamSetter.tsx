"use client";

import { useState, useRef, useEffect } from "react";
import dynamic from 'next/dynamic';
import 'react-quill-new/dist/quill.snow.css';

const ReactQuill = dynamic(() => import('react-quill-new'), {
    ssr: false,
    loading: () => <div className="h-[160px] bg-slate-50 animate-pulse rounded-[1.5rem]" />
}) as any;
import {
    Plus,
    FileQuestion,
    ChevronDown,
    Trash2,
    Save,
    LayoutList,
    FileText,
    Brain,
    Sparkles,
    Send,
    Loader2,
    Copy,
    Check,
    Upload,
    CloudUpload,
    Cpu,
    User,
    Zap,
    Scale
} from "lucide-react";

interface Message {
    role: "user" | "assistant";
    content: string;
}

export default function ExamSetter() {
    const [view, setView] = useState<'LIST' | 'CREATE'>('LIST');
    const [questionType, setQuestionType] = useState<'MCQ' | 'THEORY'>('MCQ');
    const [messages, setMessages] = useState<Message[]>([
        { role: "assistant", content: "Hello! I can help you brainstorm exam questions. Just tell me the subject and topic, and I'll generate some high-quality MCQ or Theory questions for your bank." }
    ]);
    const [chatInput, setChatInput] = useState("");
    const [bankFilter, setBankFilter] = useState<'MCQ' | 'THEORY'>('MCQ');
    const [isAILoading, setIsAILoading] = useState(false);
    const [isUploading, setIsUploading] = useState(false);
    const [newQuestion, setNewQuestion] = useState<{
        id?: string,
        subject: string,
        class: string,
        term: string,
        question: string,
        options: string[],
        answer: string,
        marks: number
    }>({
        subject: "",
        class: "",
        term: "First Term",
        question: "",
        options: ["", "", "", ""],
        answer: "",
        marks: 1
    });

    const [savedQuestions, setSavedQuestions] = useState<any[]>([]);
    const [copied, setCopied] = useState(false);
    const [teacherData, setTeacherData] = useState<{ subjects: string[], classes: string[] }>({ subjects: [], classes: [] });
    const [toast, setToast] = useState<{ show: boolean, message: string, type: 'success' | 'error' }>({ show: false, message: '', type: 'success' });
    const [selectedSubjectBank, setSelectedSubjectBank] = useState<string | null>(null);
    const [selectedClassBank, setSelectedClassBank] = useState<string | null>(null);
    const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
    const [deleteConfirm, setDeleteConfirm] = useState<{ show: boolean, id: string | string[] | null }>({ show: false, id: null });
    const chatEndRef = useRef<HTMLDivElement>(null);

    const showToast = (message: string, type: 'success' | 'error' = 'success') => {
        setToast({ show: true, message, type });
        setTimeout(() => setToast({ show: false, message: '', type: 'success' }), 5000);
    };

    const fetchQuestions = async () => {
        try {
            const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/exams/questions`, {
                headers: {
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                }
            });
            if (response.ok) {
                const data = await response.json();
                setSavedQuestions(data);
            }
        } catch (error) {
            console.error("Fetch questions error:", error);
        }
    };

    useEffect(() => {
        fetchQuestions();

        const fetchTeacherData = async () => {
            try {
                const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/my-data`, {
                    headers: {
                        "Authorization": `Bearer ${localStorage.getItem("token")}`
                    }
                });
                if (response.ok) {
                    const data = await response.json();
                    setTeacherData(data);
                    // Set defaults if available
                    if (data.subjects.length > 0) {
                        setNewQuestion(prev => ({
                            ...prev,
                            subject: data.subjects[0] || "",
                            class: "" // Let them select from the filtered list
                        }));
                    }
                }
            } catch (error) {
                console.error("Fetch teacher data error:", error);
            }
        };
        fetchTeacherData();
    }, []);

    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages]);

    const handleSendMessage = async () => {
        if (!chatInput.trim() || isAILoading) return;

        const userMessage: Message = { role: "user", content: chatInput };
        setMessages(prev => [...prev, userMessage]);
        setChatInput("");
        setIsAILoading(true);

        try {
            const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/ai/chat`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                },
                body: JSON.stringify({ message: chatInput })
            });

            if (!response.ok) throw new Error("AI failed to respond");

            const data = await response.json();
            setMessages(prev => [...prev, { role: "assistant", content: data.reply }]);
        } catch (error) {
            console.error("Chat error:", error);
            setMessages(prev => [...prev, { role: "assistant", content: "Sorry, I encountered an error. Please try again." }]);
        } finally {
            setIsAILoading(false);
        }
    };

    const applyToQuestion = (content: string) => {
        setNewQuestion(prev => ({
            ...prev,
            question: content
        }));
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;

        setIsUploading(true);
        const formData = new FormData();
        formData.append("file", file);

        const url = new URL(`${process.env.NEXT_PUBLIC_API_URL}/teacher/exams/bulk-upload`);
        if (newQuestion.subject) url.searchParams.append("subject", newQuestion.subject);
        if (newQuestion.class) url.searchParams.append("class", newQuestion.class);
        if (newQuestion.term) url.searchParams.append("term", newQuestion.term);

        try {
            const response = await fetch(url.toString(), {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                },
                body: formData
            });

            if (response.ok) {
                const data = await response.json();
                showToast(`Successfully parsed ${data.questions.length} questions from document!`, "success");
                fetchQuestions(); // Refresh the bank
            } else {
                showToast("Failed to parse document. Ensure it is a valid .docx file.", "error");
            }
        } catch (error) {
            console.error("Upload error:", error);
        } finally {
            setIsUploading(false);
        }
    };

    const handleCreate = async () => {
        try {
            const url = newQuestion.id
                ? `${process.env.NEXT_PUBLIC_API_URL}/teacher/exams/questions/${newQuestion.id}`
                : `${process.env.NEXT_PUBLIC_API_URL}/teacher/exams/questions`;
            const method = newQuestion.id ? "PUT" : "POST";

            const response = await fetch(url, {
                method,
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                },
                body: JSON.stringify({
                    ...newQuestion,
                    type: questionType
                })
            });

            if (response.ok) {
                showToast(newQuestion.id ? "Exam question updated!" : "Exam question added!", "success");
                setNewQuestion({ subject: "", class: "", term: "First Term", question: "", answer: "", options: ["", "", "", ""], marks: 1 });
                fetchQuestions();
                setView('LIST');
            } else {
                const errorData = await response.json();
                showToast(`Error: ${errorData.error || "Failed to save question"}`, "error");
            }
        } catch (error) {
            console.error("Create error:", error);
        }
    };

    const handleDeleteQuestion = (id: string) => {
        setDeleteConfirm({ show: true, id });
    };

    const confirmDelete = async () => {
        if (!deleteConfirm.id) return;
        try {
            const isBulk = Array.isArray(deleteConfirm.id);
            const url = isBulk 
                ? `${process.env.NEXT_PUBLIC_API_URL}/teacher/exams/questions/bulk-delete`
                : `${process.env.NEXT_PUBLIC_API_URL}/teacher/exams/questions/${deleteConfirm.id}`;
            const method = isBulk ? "POST" : "DELETE";
            const body = isBulk ? JSON.stringify({ ids: deleteConfirm.id }) : undefined;

            const response = await fetch(url, {
                method,
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                },
                body
            });
            if (response.ok) {
                showToast(isBulk ? "Questions deleted!" : "Exam question deleted!", "success");
                setSelectedIds(new Set());
                fetchQuestions();
            } else {
                showToast("Failed to delete.", "error");
            }
        } catch (error) {
            console.error("Delete error:", error);
            showToast("An error occurred while deleting.", "error");
        } finally {
            setDeleteConfirm({ show: false, id: null });
        }
    };

    const toggleSelect = (id: string) => {
        const next = new Set(selectedIds);
        if (next.has(id)) {
            next.delete(id);
        } else {
            next.add(id);
        }
        setSelectedIds(next);
    };

    const toggleSelectAll = (questions: any[]) => {
        if (selectedIds.size === questions.length && questions.length > 0) {
            setSelectedIds(new Set());
        } else {
            setSelectedIds(new Set(questions.map(q => q.id)));
        }
    };

    const handleEditQuestion = (q: any) => {
        setQuestionType(q.type);
        setNewQuestion({
            id: q.id,
            subject: q.subject,
            class: q.class,
            term: q.term || "First Term",
            question: q.question,
            options: q.options || ["", "", "", ""],
            answer: q.answer,
            marks: q.marks || 1
        });
        setView('CREATE');
    };

    return (
        <div className="flex flex-col gap-8 relative">
            {/* Custom Toast Notification */}
            {toast.show && (
                <div className={`absolute top-0 right-0 z-50 flex items-center space-x-3 px-6 py-4 rounded-2xl shadow-2xl transition-all animate-in fade-in slide-in-from-top-5 duration-300 ${toast.type === 'success' ? 'bg-emerald-50 text-emerald-600 border border-emerald-200' : 'bg-red-50 text-red-600 border border-red-200'}`}>
                    <div className={`p-2 rounded-xl ${toast.type === 'success' ? 'bg-emerald-100' : 'bg-red-100'}`}>
                        {toast.type === 'success' ? <Check className="w-5 h-5" /> : <div className="w-5 h-5 flex justify-center items-center font-bold">!</div>}
                    </div>
                    <div>
                        <p className="font-bold text-[15px]">{toast.type === 'success' ? 'Success' : 'Error'}</p>
                        <p className="text-sm font-medium opacity-90">{toast.message}</p>
                    </div>
                </div>
            )}

            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div>
                    <h2 className="text-2xl lg:text-3xl font-black text-slate-800 tracking-tight">Exam Question Setter</h2>
                    <p className="text-slate-500 text-sm font-medium">Build robust question banks for students</p>
                </div>
                <div className="flex flex-wrap items-center gap-3 lg:space-x-4">
                    {(view === 'CREATE' || selectedSubjectBank) && (
                        <label className="flex items-center space-x-2 bg-white border-2 border-slate-100 px-4 lg:px-6 py-2.5 lg:py-3 rounded-xl lg:rounded-2xl font-bold cursor-pointer hover:border-indigo-500/20 hover:bg-slate-50 transition-all text-slate-600 shadow-sm active:scale-95 text-xs lg:text-sm">
                            <Upload className="w-4 h-4 lg:w-5 lg:h-5 text-indigo-500" />
                            <span>{isUploading ? "Processing..." : "Bulk Upload"}</span>
                            <input type="file" className="hidden" accept=".docx" onChange={handleFileUpload} disabled={isUploading} />
                        </label>
                    )}
                    <button
                        onClick={() => {
                            setSelectedSubjectBank(null);
                            setSelectedClassBank(null);
                            setSelectedIds(new Set());
                            setView('LIST');
                        }}
                        className={`px-4 lg:px-5 py-2.5 lg:py-3 rounded-xl lg:rounded-2xl font-bold text-xs lg:text-sm transition-all ${view === 'LIST' ? 'bg-indigo-50 text-indigo-700' : 'text-slate-400 hover:text-slate-600'}`}
                    >
                        Bank
                    </button>
                    <button
                        onClick={() => {
                            setNewQuestion({ subject: teacherData.subjects[0] || "", class: teacherData.classes[0] || "", term: "First Term", question: "", answer: "", options: ["", "", "", ""], marks: 1 });
                            setView('CREATE');
                        }}
                        className={`px-6 lg:px-8 py-3 lg:py-4 rounded-xl lg:rounded-[1.5rem] font-bold transition-all shadow-xl flex items-center space-x-2 text-xs lg:text-sm ${view === 'CREATE' ? 'bg-slate-900 text-white shadow-slate-900/20' : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-50'}`}
                    >
                        <Plus className="w-4 h-4 lg:w-5 lg:h-5" />
                        <span>Add New</span>
                    </button>
                </div>
            </div>

            {view === 'CREATE' && (
                <div className="flex flex-col lg:flex-row gap-8">
                    {/* Form Section */}
                    <div className="flex-1 space-y-8">
                        <div className="bg-white rounded-[2.5rem] border border-slate-200 p-10 space-y-10 shadow-xl shadow-slate-200/40">
                            <div className="flex p-1.5 bg-slate-100 rounded-[1.5rem] w-fit">
                                <button
                                    onClick={() => setQuestionType('MCQ')}
                                    className={`px-8 py-3 rounded-[1.25rem] text-sm font-black uppercase tracking-widest transition-all ${questionType === 'MCQ' ? 'bg-white text-indigo-600 shadow-lg' : 'text-slate-400'}`}
                                >
                                    Multiple Choice
                                </button>
                                <button
                                    onClick={() => setQuestionType('THEORY')}
                                    className={`px-8 py-3 rounded-[1.25rem] text-sm font-black uppercase tracking-widest transition-all ${questionType === 'THEORY' ? 'bg-white text-indigo-600 shadow-lg' : 'text-slate-400'}`}
                                >
                                    Theory/Essay
                                </button>
                            </div>

                            <div className="space-y-8">
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                    <div className="space-y-3">
                                        <label className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Subject</label>
                                        <select
                                            className="w-full bg-slate-50 border-2 border-transparent focus:border-indigo-500/20 focus:bg-white rounded-2xl px-6 py-4 outline-none transition-all font-bold text-slate-700 appearance-none cursor-pointer"
                                            value={newQuestion.subject}
                                            onChange={(e) => setNewQuestion({ ...newQuestion, subject: e.target.value })}
                                        >
                                            <option value="">Select Subject</option>
                                            {teacherData.subjects.map((sub, i) => (
                                                <option key={i} value={sub}>{sub}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div className="space-y-3">
                                        <label className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Target Class</label>
                                        <select
                                            className="w-full bg-slate-50 border-2 border-transparent focus:border-indigo-500/20 focus:bg-white rounded-2xl px-6 py-4 outline-none transition-all font-bold text-slate-700 appearance-none cursor-pointer"
                                            value={newQuestion.class}
                                            onChange={(e) => setNewQuestion({ ...newQuestion, class: e.target.value })}
                                        >
                                            <option key="default" value="">Select Class</option>
                                            {(() => {
                                                const isJunior = teacherData.classes.some(c => c.toUpperCase().includes('JS')) || 
                                                                teacherData.subjects.some(s => s.toUpperCase().includes('JS') || s.toUpperCase().includes('JUNIOR'));
                                                const isSenior = teacherData.classes.some(c => c.toUpperCase().includes('SS')) || 
                                                                teacherData.subjects.some(s => s.toUpperCase().includes('SS') || s.toUpperCase().includes('SENIOR'));
                                                
                                                const options = [];
                                                if (isJunior || (!isJunior && !isSenior)) {
                                                    options.push("JS 1", "JS 2", "JS 3");
                                                }
                                                if (isSenior || (!isJunior && !isSenior)) {
                                                    options.push("SS 1", "SS 2", "SS 3");
                                                }
                                                
                                                return Array.from(new Set(options)).map((cls, i) => (
                                                    <option key={i} value={cls}>{cls}</option>
                                                ));
                                            })()}
                                        </select>
                                    </div>
                                    <div className="space-y-3">
                                        <label className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Marks</label>
                                        <input
                                            type="number"
                                            className="w-full bg-slate-50 border-2 border-transparent focus:border-indigo-500/20 focus:bg-white rounded-2xl px-6 py-4 outline-none transition-all font-bold text-slate-700"
                                            value={newQuestion.marks}
                                            onChange={(e) => setNewQuestion({ ...newQuestion, marks: parseInt(e.target.value) })}
                                        />
                                    </div>
                                </div>

                                <div className="space-y-3">
                                    <label className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Question Body</label>
                                    <div className="bg-slate-50 border-2 border-transparent focus-within:border-indigo-500/20 focus-within:bg-white rounded-[1.5rem] overflow-hidden transition-all">
                                        <ReactQuill
                                            theme="snow"
                                            value={newQuestion.question}
                                            onChange={(val: string) => setNewQuestion({ ...newQuestion, question: val })}
                                            placeholder="Type your question or use AI to generate ideas..."
                                            className="font-medium text-slate-700 leading-relaxed text-lg"
                                        />
                                    </div>
                                    <style jsx global>{`
                                        .ql-toolbar.ql-snow {
                                            border: none !important;
                                            background: #f8fafc;
                                            padding: 12px 20px !important;
                                        }
                                        .ql-container.ql-snow {
                                            border: none !important;
                                            min-height: 160px;
                                            font-size: 1.125rem !important;
                                        }
                                        .ql-editor {
                                            padding: 24px 32px !important;
                                        }
                                        .ql-editor.ql-blank::before {
                                            left: 32px !important;
                                            color: #cbd5e1 !important;
                                            font-style: normal !important;
                                        }
                                    `}</style>
                                </div>

                                {questionType === 'MCQ' ? (
                                    <div className="space-y-6">
                                        <label className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Options & Correct Answer</label>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                            {newQuestion.options.map((opt, i) => (
                                                <div key={i} className="flex items-center space-x-4 bg-slate-50 border-2 border-transparent focus-within:border-indigo-500/20 focus-within:bg-white rounded-2xl px-6 py-3 transition-all">
                                                    <span className="font-black text-indigo-500 text-lg w-6">{String.fromCharCode(65 + i)}</span>
                                                    <input
                                                        type="text"
                                                        placeholder={`Option ${String.fromCharCode(65 + i)}`}
                                                        className="w-full bg-transparent border-none focus:outline-none font-bold py-2 text-slate-700"
                                                        value={opt}
                                                        onChange={(e) => {
                                                            const newOpts = [...newQuestion.options];
                                                            newOpts[i] = e.target.value;
                                                            setNewQuestion({ ...newQuestion, options: newOpts });
                                                        }}
                                                    />
                                                </div>
                                            ))}
                                        </div>
                                        <div className="pt-4 border-t border-slate-100">
                                            <select
                                                className="w-full bg-slate-900 text-white rounded-2xl px-8 py-4 focus:outline-none font-black text-sm uppercase tracking-widest cursor-pointer shadow-lg shadow-slate-900/20"
                                                value={newQuestion.answer}
                                                onChange={(e) => setNewQuestion({ ...newQuestion, answer: e.target.value })}
                                            >
                                                <option value="">Select correct option Letter</option>
                                                <option value="A">Option A</option>
                                                <option value="B">Option B</option>
                                                <option value="C">Option C</option>
                                                <option value="D">Option D</option>
                                            </select>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="bg-indigo-50/50 rounded-2xl p-6 border border-indigo-100/50">
                                        <div className="flex items-center space-x-3 text-indigo-700 mb-2">
                                            <Sparkles className="w-5 h-5" />
                                            <span className="font-bold">Theory Question Mode</span>
                                        </div>
                                        <p className="text-sm text-indigo-600/80 font-medium leading-relaxed">
                                            No scoring guide is required. Teachers will manually review and score student responses after the exam is attempted.
                                        </p>
                                    </div>
                                )}

                                <button
                                    onClick={handleCreate}
                                    className="w-full bg-indigo-600 hover:bg-indigo-700 text-white py-5 rounded-[1.5rem] font-black uppercase tracking-widest text-sm transition-all shadow-xl shadow-indigo-600/20 flex items-center justify-center space-x-3 active:scale-[0.98]"
                                >
                                    <Save className="w-5 h-5" />
                                    <span>{newQuestion.id ? "Update Question" : "Save Question to Bank"}</span>
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* Premium AI Sidebar */}
                    <div className="w-full lg:w-[480px] bg-slate-950 rounded-[2.5rem] overflow-hidden flex flex-col shadow-2xl shadow-slate-900/40 border border-white/5 h-[500px] lg:h-[calc(100vh-250px)]">
                        {/* AI Header */}
                        <div className="p-6 border-b border-white/5 bg-slate-900/50 backdrop-blur-xl flex items-center justify-between">
                            <div className="flex items-center space-x-4">
                                <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-indigo-700 rounded-2xl flex items-center justify-center text-white shadow-lg shadow-indigo-500/20 ring-4 ring-white/5">
                                    <Sparkles className="w-6 h-6" />
                                </div>
                                <div>
                                    <div className="flex items-center space-x-2">
                                        <h3 className="text-white font-black tracking-tight">Exam AI</h3>
                                        <div className="px-2 py-0.5 bg-indigo-500/10 text-indigo-400 text-[8px] font-black uppercase tracking-widest rounded-full border border-indigo-500/20">Active</div>
                                    </div>
                                    <div className="flex items-center space-x-2 text-[10px] text-slate-400 font-bold">
                                        <Zap className="w-3 h-3 text-emerald-500" />
                                        <span>Pro Mode Engaged</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Messages Container */}
                        <div className="flex-1 overflow-y-auto p-8 space-y-8 scrollbar-hide">
                            {messages.map((msg, i) => (
                                <div key={i} className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'} space-y-2`}>
                                    <div className="flex items-center space-x-2 px-1">
                                        {msg.role === 'assistant' ? (
                                            <div className="flex items-center space-x-2">
                                                <div className="w-5 h-5 bg-indigo-500/20 rounded flex items-center justify-center">
                                                    <Cpu className="w-3 h-3 text-indigo-400" />
                                                </div>
                                                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Bot</span>
                                            </div>
                                        ) : (
                                            <div className="flex items-center space-x-2">
                                                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">You</span>
                                                <div className="w-5 h-5 bg-emerald-500/20 rounded flex items-center justify-center">
                                                    <User className="w-3 h-3 text-emerald-400" />
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                    <div className={`relative max-w-[90%] rounded-[1.5rem] px-6 py-4 text-[15px] leading-relaxed transition-all ${msg.role === 'user'
                                        ? 'bg-emerald-600 text-white rounded-tr-none shadow-lg shadow-emerald-600/10'
                                        : 'bg-slate-900 text-slate-200 rounded-tl-none border border-white/5'
                                        }`}>
                                        <div className="whitespace-pre-wrap">{msg.content}</div>

                                        {msg.role === 'assistant' && i !== 0 && (
                                            <div className="mt-6 flex items-center space-x-3 pt-4 border-t border-white/5">
                                                <button
                                                    onClick={() => applyToQuestion(msg.content)}
                                                    className="flex items-center space-x-2 text-[10px] font-black uppercase tracking-[0.15em] bg-indigo-500 hover:bg-indigo-400 text-white px-4 py-2 rounded-xl transition-all active:scale-95 shadow-lg shadow-indigo-500/20"
                                                >
                                                    {copied ? <Check className="w-3 h-3" /> : <Plus className="w-3 h-3" />}
                                                    <span>Populate Form</span>
                                                </button>
                                                <button className="p-2 bg-white/5 hover:bg-white/10 rounded-xl transition-all text-slate-400 hover:text-white">
                                                    <Copy className="w-3 h-3" />
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))}
                            {isAILoading && (
                                <div className="flex items-start flex-col space-y-2">
                                    <div className="flex items-center space-x-2 px-1">
                                        <div className="w-5 h-5 bg-indigo-500/20 rounded flex items-center justify-center">
                                            <Cpu className="w-3 h-3 text-indigo-400" />
                                        </div>
                                        <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Processing...</span>
                                    </div>
                                    <div className="bg-slate-900 rounded-[1.5rem] rounded-tl-none p-6 border border-white/5 flex space-x-2">
                                        <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce [animation-delay:-0.3s]"></div>
                                        <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce [animation-delay:-0.15s]"></div>
                                        <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce"></div>
                                    </div>
                                </div>
                            )}
                            <div ref={chatEndRef} />
                        </div>

                        {/* Input Area */}
                        <div className="p-8 bg-slate-900/50 backdrop-blur-xl border-t border-white/5">
                            <div className="relative group">
                                <textarea
                                    rows={1}
                                    placeholder="Ask for question ideas..."
                                    className="w-full bg-slate-800/50 border-2 border-white/5 rounded-[1.5rem] pl-6 pr-16 py-5 text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500/50 focus:bg-slate-800 transition-all font-medium text-base resize-none overflow-hidden"
                                    value={chatInput}
                                    onChange={(e) => setChatInput(e.target.value)}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter' && !e.shiftKey) {
                                            e.preventDefault();
                                            handleSendMessage();
                                        }
                                    }}
                                />
                                <button
                                    onClick={handleSendMessage}
                                    disabled={isAILoading || !chatInput.trim()}
                                    className="absolute right-3 top-3 p-3 bg-white text-slate-950 hover:bg-indigo-400 transition-all rounded-xl shadow-xl active:scale-90 flex items-center justify-center disabled:opacity-20"
                                >
                                    <Send className="w-5 h-5 translate-x-0.5 -translate-y-0.5" />
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {view === 'LIST' && (
                <div className="bg-white rounded-[3rem] border border-slate-100 p-10 shadow-2xl shadow-slate-100/50 min-h-[500px]">
                    {!selectedSubjectBank ? (
                        <>
                            <div className="flex items-center space-x-4 mb-8">
                                <div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center">
                                    <FileQuestion className="w-6 h-6" />
                                </div>
                                <div>
                                    <h3 className="text-xl font-black text-slate-800 tracking-tight">Your Subjects</h3>
                                    <p className="text-sm font-medium text-slate-500">Select a subject to view its question bank</p>
                                </div>
                            </div>

                            {teacherData.subjects.length === 0 ? (
                                <div className="text-center py-20 px-6 bg-slate-50 rounded-[2rem] border-2 border-dashed border-slate-200">
                                    <p className="text-slate-500 font-bold">No subjects assigned yet.</p>
                                </div>
                            ) : (
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                    {teacherData.subjects.map(subject => {
                                        const count = savedQuestions.filter(q => q.subject === subject).length;
                                        return (
                                            <button
                                                key={subject}
                                                onClick={() => setSelectedSubjectBank(subject)}
                                                className="flex flex-col text-left p-6 rounded-[1.5rem] border-2 border-slate-100 hover:border-indigo-500/30 hover:bg-slate-50 transition-all group"
                                            >
                                                <span className="text-lg font-black text-slate-800 mb-2 group-hover:text-indigo-600 transition-colors">{subject}</span>
                                                <div className="flex items-center space-x-2 text-sm font-bold text-slate-500">
                                                    <span className="px-3 py-1 bg-slate-100 rounded-lg group-hover:bg-indigo-50 group-hover:text-indigo-600 transition-colors">{count} Question{count !== 1 ? 's' : ''}</span>
                                                </div>
                                            </button>
                                        );
                                    })}
                                </div>
                            )}
                        </>
                    ) : (
                        <>
                            <div className="flex items-center justify-between mb-8 pb-6 border-b border-slate-100">
                                <div className="flex items-center space-x-4">
                                    <button
                                        onClick={() => {
                                            if (selectedClassBank) {
                                                setSelectedClassBank(null);
                                            } else {
                                                setSelectedSubjectBank(null);
                                            }
                                            setSelectedIds(new Set());
                                        }}
                                        className="p-3 bg-slate-50 hover:bg-slate-100 text-slate-500 hover:text-slate-800 rounded-2xl transition-colors"
                                    >
                                        <ChevronDown className="w-6 h-6 rotate-90" />
                                    </button>
                                    <div>
                                        <h3 className="text-xl font-black text-slate-800 tracking-tight">{selectedSubjectBank} {selectedClassBank ? `- Class ${selectedClassBank}` : ''} Bank</h3>
                                        <p className="text-sm font-medium text-slate-500">
                                            {selectedClassBank 
                                                ? `${savedQuestions.filter(q => q.subject === selectedSubjectBank && q.class === selectedClassBank).length} Questions for this class` 
                                                : `${savedQuestions.filter(q => q.subject === selectedSubjectBank).length} Total Questions`
                                            }
                                        </p>
                                    </div>
                                </div>
                                <div className="flex items-center space-x-3">
                                    {selectedIds.size > 0 && (
                                        <button
                                            onClick={() => setDeleteConfirm({ show: true, id: Array.from(selectedIds) })}
                                            className="bg-red-50 hover:bg-red-100 text-red-600 px-6 py-3 rounded-xl font-bold transition-all flex items-center space-x-2"
                                        >
                                            <Trash2 className="w-4 h-4" />
                                            <span>Delete Selected ({selectedIds.size})</span>
                                        </button>
                                    )}
                                    <button
                                        onClick={() => {
                                            setNewQuestion({ 
                                                subject: selectedSubjectBank, 
                                                class: selectedClassBank || teacherData.classes[0] || "", 
                                                term: "First Term", 
                                                question: "", 
                                                answer: "", 
                                                options: ["", "", "", ""], 
                                                marks: 1 
                                            });
                                            setView('CREATE');
                                        }}
                                        className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 border border-indigo-700/50 rounded-xl font-bold transition-all shadow-xl shadow-indigo-600/20 active:scale-95 flex items-center space-x-2"
                                    >
                                        <Plus className="w-4 h-4" />
                                        <span>Add Question</span>
                                    </button>
                                </div>
                            </div>

                             <div className="flex items-center justify-between mb-8">
                                <div className="flex p-1 bg-slate-100 rounded-2xl w-fit">
                                    <button
                                        onClick={() => {
                                            setBankFilter('MCQ');
                                            setSelectedIds(new Set());
                                        }}
                                        className={`px-8 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${bankFilter === 'MCQ' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-500 hover:text-slate-800'}`}
                                    >
                                        Objectives (MCQ)
                                    </button>
                                    <button
                                        onClick={() => {
                                            setBankFilter('THEORY');
                                            setSelectedIds(new Set());
                                        }}
                                        className={`px-8 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${bankFilter === 'THEORY' ? 'bg-white text-indigo-600 shadow-sm' : 'text-slate-500 hover:text-slate-800'}`}
                                    >
                                        Theory/Essay
                                    </button>
                                </div>

                                {savedQuestions.filter(q => q.subject === selectedSubjectBank && q.type === bankFilter && (selectedClassBank ? q.class === selectedClassBank : true)).length > 0 && (
                                    <label className="flex items-center space-x-3 cursor-pointer group">
                                        <div 
                                            onClick={() => toggleSelectAll(savedQuestions.filter(q => q.subject === selectedSubjectBank && q.type === bankFilter && (selectedClassBank ? q.class === selectedClassBank : true)))}
                                            className={`w-6 h-6 rounded-lg border-2 flex items-center justify-center transition-all ${
                                                selectedIds.size === savedQuestions.filter(q => q.subject === selectedSubjectBank && q.type === bankFilter && (selectedClassBank ? q.class === selectedClassBank : true)).length && selectedIds.size > 0
                                                ? 'bg-indigo-600 border-indigo-600' 
                                                : 'bg-white border-slate-200 group-hover:border-indigo-400'
                                            }`}
                                        >
                                            {selectedIds.size === savedQuestions.filter(q => q.subject === selectedSubjectBank && q.type === bankFilter && (selectedClassBank ? q.class === selectedClassBank : true)).length && selectedIds.size > 0 && <Check className="w-4 h-4 text-white" />}
                                        </div>
                                        <span className="text-sm font-bold text-slate-600">Select All</span>
                                    </label>
                                )}
                            </div>

                            {!selectedClassBank ? (
                                <>
                                    <div className="flex items-center space-x-4 mb-8">
                                        <div className="w-12 h-12 bg-amber-50 text-amber-600 rounded-2xl flex items-center justify-center">
                                            <LayoutList className="w-6 h-6" />
                                        </div>
                                        <div>
                                            <h3 className="text-xl font-black text-slate-800 tracking-tight">Select Class</h3>
                                            <p className="text-sm font-medium text-slate-500">Pick a class to view its {bankFilter === 'MCQ' ? 'Objective' : 'Theory'} questions</p>
                                        </div>
                                    </div>

                                    {Array.from(new Set(savedQuestions.filter(q => q.subject === selectedSubjectBank && q.type === bankFilter).map(q => q.class))).length === 0 ? (
                                        <div className="text-center py-20 px-6 bg-slate-50 rounded-[2rem] border-2 border-dashed border-slate-200">
                                            <div className="w-20 h-20 bg-white rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-sm">
                                                <FileQuestion className="w-8 h-8 text-slate-300" />
                                            </div>
                                            <h3 className="text-xl font-black text-slate-800 mb-2">No {bankFilter === 'MCQ' ? 'Objective' : 'Theory'} Questions Yet</h3>
                                            <p className="text-slate-500 font-medium mb-8 max-w-sm mx-auto">This section is currently empty for {selectedSubjectBank}.</p>
                                        </div>
                                    ) : (
                                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                            {Array.from(new Set(savedQuestions.filter(q => q.subject === selectedSubjectBank && q.type === bankFilter).map(q => q.class))).sort().map(cls => {
                                                const count = savedQuestions.filter(q => q.subject === selectedSubjectBank && q.type === bankFilter && q.class === cls).length;
                                                return (
                                                    <button
                                                        key={cls}
                                                        onClick={() => setSelectedClassBank(cls)}
                                                        className="flex flex-col text-left p-6 rounded-[1.5rem] border-2 border-slate-100 hover:border-indigo-500/30 hover:bg-slate-50 transition-all group"
                                                    >
                                                        <span className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] mb-2">Class</span>
                                                        <span className="text-lg font-black text-slate-800 mb-2 group-hover:text-indigo-600 transition-colors">{cls}</span>
                                                        <div className="flex items-center space-x-2 text-sm font-bold text-slate-500">
                                                            <span className="px-3 py-1 bg-slate-100 rounded-lg group-hover:bg-indigo-50 group-hover:text-indigo-600 transition-colors">{count} Question{count !== 1 ? 's' : ''}</span>
                                                        </div>
                                                    </button>
                                                );
                                            })}
                                        </div>
                                    )}
                                </>
                            ) : (
                                <>
                                    {savedQuestions.filter(q => q.subject === selectedSubjectBank && q.type === bankFilter && q.class === selectedClassBank).length === 0 ? (
                                        <div className="flex flex-col items-center justify-center h-full text-center py-20 bg-slate-50 rounded-[2rem] border-2 border-dashed border-slate-200">
                                            <div className="w-20 h-20 bg-white rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-sm">
                                                <FileQuestion className="w-8 h-8 text-slate-300" />
                                            </div>
                                            <h3 className="text-xl font-black text-slate-800 mb-2">No {bankFilter === 'MCQ' ? 'Objective' : 'Theory'} Questions Yet</h3>
                                            <p className="text-slate-500 font-medium mb-8 max-w-sm mx-auto">This section is currently empty for Class {selectedClassBank}.</p>
                                        </div>
                                    ) : (
                                        <div className="space-y-6">
                                            {savedQuestions.filter(q => q.subject === selectedSubjectBank && q.type === bankFilter && q.class === selectedClassBank).map((q) => (
                                                <div key={q.id} className={`p-6 border-2 rounded-[1.5rem] transition-all group flex flex-col space-y-4 ${selectedIds.has(q.id) ? 'border-indigo-500 bg-indigo-50/30' : 'border-slate-100 bg-white hover:border-indigo-500/30 hover:shadow-lg hover:shadow-slate-200/50'}`}>
                                                    <div className="flex justify-between items-start">
                                                        <div className="flex items-center space-x-4">
                                                            <div 
                                                                onClick={() => toggleSelect(q.id)}
                                                                className={`w-6 h-6 rounded-lg border-2 flex items-center justify-center transition-all cursor-pointer ${
                                                                    selectedIds.has(q.id) 
                                                                    ? 'bg-indigo-600 border-indigo-600' 
                                                                    : 'bg-white border-slate-200 hover:border-indigo-400'
                                                                }`}
                                                            >
                                                                {selectedIds.has(q.id) && <Check className="w-4 h-4 text-white" />}
                                                            </div>
                                                            <div className="flex items-center space-x-3">
                                                                <span className="px-3 py-1 bg-indigo-50 text-indigo-600 rounded-lg text-xs font-black uppercase tracking-wider">{q.type}</span>
                                                                <span className="px-3 py-1 bg-slate-100 text-slate-600 rounded-lg text-xs font-bold">Class {q.class}</span>
                                                                <span className="px-3 py-1 bg-amber-50 text-amber-600 rounded-lg text-xs font-bold">{q.marks} Mark(s)</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div className="text-slate-800 font-medium text-lg list-disc-inside" dangerouslySetInnerHTML={{ __html: q.question || '' }} />

                                                    {q.type === 'MCQ' && q.options && q.options.length > 0 && (
                                                        <div className="grid grid-cols-2 gap-4 mt-4">
                                                            {q.options.map((opt: string, idx: number) => (
                                                                <div key={idx} className={`p-3 rounded-xl border ${String.fromCharCode(65 + idx) === q.answer ? 'bg-emerald-50 border-emerald-200' : 'bg-slate-50 border-slate-100'}`}>
                                                                    <span className={`font-bold mr-2 ${String.fromCharCode(65 + idx) === q.answer ? 'text-emerald-600' : 'text-slate-400'}`}>{String.fromCharCode(65 + idx)})</span>
                                                                    <span className={String.fromCharCode(65 + idx) === q.answer ? 'text-emerald-900 font-medium' : 'text-slate-600'}>{opt}</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}

                                                    {q.type === 'THEORY' && (
                                                        <div className="mt-4 p-4 bg-indigo-50/30 rounded-xl border border-indigo-100/50">
                                                            <div className="flex items-center space-x-2 text-indigo-600">
                                                                <Sparkles className="w-4 h-4" />
                                                                <span className="text-xs font-black uppercase tracking-widest">Grading Note</span>
                                                            </div>
                                                            <p className="text-xs text-indigo-500 font-medium mt-1 leading-relaxed">
                                                                Manual grading required after student attempt.
                                                            </p>
                                                        </div>
                                                    )}

                                                    <div className="flex items-center space-x-3 pt-4 border-t border-slate-100 mt-2">
                                                        <button
                                                            onClick={() => handleEditQuestion(q)}
                                                            className="px-6 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold rounded-xl transition-colors text-sm"
                                                        >
                                                            Edit
                                                        </button>
                                                        <button
                                                            onClick={() => handleDeleteQuestion(q.id)}
                                                            className="px-6 py-2 bg-red-50 hover:bg-red-100 text-red-600 font-bold rounded-xl transition-colors text-sm"
                                                        >
                                                            Delete
                                                        </button>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </>
                            )}
                        </>
                    )}
                </div>
            )}
            {/* Delete Confirmation Modal */}
            {deleteConfirm.show && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
                    <div className="absolute inset-0 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-300" onClick={() => setDeleteConfirm({ show: false, id: null })} />
                    <div className="bg-white rounded-[2rem] p-8 max-w-md w-full relative z-10 shadow-2xl border border-slate-100 animate-in zoom-in-95 duration-300">
                        <div className="w-16 h-16 bg-red-50 rounded-2xl flex items-center justify-center mb-6">
                            <Trash2 className="w-8 h-8 text-red-500" />
                        </div>
                        <h3 className="text-2xl font-bold text-slate-900 mb-2">{Array.isArray(deleteConfirm.id) ? 'Bulk Delete Questions?' : 'Delete Question?'}</h3>
                        <p className="text-slate-500 font-medium mb-8">
                            {Array.isArray(deleteConfirm.id) 
                                ? `Are you sure you want to delete ${deleteConfirm.id.length} exam questions? This action cannot be undone and will remove them from your question bank.`
                                : "Are you sure you want to delete this exam question? This action cannot be undone and will remove it from your question bank."
                            }
                        </p>
                        <div className="grid grid-cols-2 gap-4">
                            <button
                                onClick={() => setDeleteConfirm({ show: false, id: null })}
                                className="py-4 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold rounded-2xl transition-all active:scale-95"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={confirmDelete}
                                className="py-4 bg-red-500 hover:bg-red-600 text-white font-bold rounded-2xl transition-all shadow-lg shadow-red-500/20 active:scale-95"
                            >
                                Yes, Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
