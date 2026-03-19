"use client";

import { useState, useEffect, useRef } from "react";
import dynamic from 'next/dynamic';
import 'react-quill-new/dist/quill.snow.css';

const ReactQuill = dynamic(() => import('react-quill-new'), {
    ssr: false,
    loading: () => <div className="h-[400px] bg-slate-50 animate-pulse rounded-[2rem]" />
}) as any;

import {
    Send,
    Bot,
    User,
    Plus,
    Save,
    BookOpen,
    Sparkles,
    Copy,
    Check,
    ChevronRight,
    Loader2,
    MessageSquare,
    Zap,
    Cpu,
    SquarePen
} from "lucide-react";

interface Message {
    role: "user" | "assistant";
    content: string;
}

interface Note {
    id?: string;
    subject: string;
    topic: string;
    content: string;
    class: string;
}

export default function LessonNotebook() {
    const [messages, setMessages] = useState<Message[]>([
        { role: "assistant", content: "Hello! I'm your AI Lesson Assistant. I can help you draft notes, create outlines, or explain complex educational concepts. What are we working on today?" }
    ]);
    const [input, setInput] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [currentNote, setCurrentNote] = useState<Note>({
        subject: "",
        topic: "",
        content: "",
        class: ""
    });
    const [copied, setCopied] = useState(false);
    const [model, setModel] = useState("GPT-4o");
    const [teacherData, setTeacherData] = useState<{ subjects: string[], classes: string[] }>({ subjects: [], classes: [] });
    const [toast, setToast] = useState<{ show: boolean, message: string, type: 'success' | 'error' }>({ show: false, message: '', type: 'success' });
    const [view, setView] = useState<'CREATE' | 'LIST'>('CREATE');
    const [savedNotes, setSavedNotes] = useState<Note[]>([]);
    const chatEndRef = useRef<HTMLDivElement>(null);

    const showToast = (message: string, type: 'success' | 'error' = 'success') => {
        setToast({ show: true, message, type });
        setTimeout(() => setToast({ show: false, message: '', type: 'success' }), 5000);
    };

    const fetchNotes = async () => {
        try {
            const response = await fetch("http://localhost:4000/api/teacher/lesson-notes", {
                headers: {
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                }
            });
            if (response.ok) {
                const data = await response.json();
                setSavedNotes(data);
            }
        } catch (error) {
            console.error("Fetch notes error:", error);
        }
    };

    useEffect(() => {
        fetchNotes();

        const fetchTeacherData = async () => {
            try {
                const response = await fetch("http://localhost:4000/api/teacher/my-data", {
                    headers: {
                        "Authorization": `Bearer ${localStorage.getItem("token")}`
                    }
                });
                if (response.ok) {
                    const data = await response.json();
                    setTeacherData(data);
                    // Set defaults if available
                    if (data.subjects.length > 0 || data.classes.length > 0) {
                        setCurrentNote(prev => ({
                            ...prev,
                            subject: data.subjects[0] || "",
                            class: data.classes[0] || ""
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
        if (!input.trim() || isLoading) return;

        const userMessage: Message = { role: "user", content: input };
        setMessages(prev => [...prev, userMessage]);
        setInput("");
        setIsLoading(true);

        try {
            const response = await fetch("http://localhost:4000/api/teacher/ai/chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                },
                body: JSON.stringify({ message: input })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || "AI failed to respond");
            }

            const data = await response.json();
            setMessages(prev => [...prev, { role: "assistant", content: data.reply }]);
        } catch (error) {
            console.error("Chat error:", error);
            setMessages(prev => [...prev, { role: "assistant", content: "Sorry, I encountered an error. Please check your connection and try again." }]);
        } finally {
            setIsLoading(false);
        }
    };

    const handleSaveNote = async () => {
        if (!currentNote.subject || !currentNote.class || !currentNote.topic || !currentNote.content) {
            showToast("Please fill in all fields (Subject, Class, Topic, and Lesson Content) before saving.", "error");
            return;
        }

        try {
            const url = currentNote.id
                ? `http://localhost:4000/api/teacher/lesson-notes/${currentNote.id}`
                : "http://localhost:4000/api/teacher/lesson-notes";
            const method = currentNote.id ? "PUT" : "POST";

            const response = await fetch(url, {
                method,
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                },
                body: JSON.stringify(currentNote)
            });

            if (response.ok) {
                showToast(currentNote.id ? "Lesson note updated successfully!" : "Lesson note saved successfully!", "success");
                setCurrentNote({ subject: "", topic: "", content: "", class: "" }); // retain defaults based on teacherData if preferred, but reset ID
                fetchNotes(); // Refresh list
                setView('LIST'); // go to list
            } else {
                const errorData = await response.json();
                showToast(`Failed to save note: ${errorData.error || response.statusText}`, "error");
                console.error("Backend error:", errorData);
            }
        } catch (error) {
            console.error("Save error:", error);
            showToast("An error occurred while saving. Please check your network connection.", "error");
        }
    };

    const applyToNote = (content: string) => {
        setCurrentNote(prev => ({
            ...prev,
            content: prev.content + (prev.content ? "\n\n" : "") + content
        }));
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleDeleteNote = async (id: string) => {
        if (!confirm("Are you sure you want to delete this lesson note?")) return;
        try {
            const response = await fetch(`http://localhost:4000/api/teacher/lesson-notes/${id}`, {
                method: "DELETE",
                headers: {
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                }
            });
            if (response.ok) {
                showToast("Lesson note deleted!", "success");
                fetchNotes();
            } else {
                showToast("Failed to delete lesson note.", "error");
            }
        } catch (error) {
            console.error(error);
            showToast("Error deleting note.", "error");
        }
    };

    const handleEditNote = (note: Note) => {
        setCurrentNote(note);
        setView('CREATE');
    };

    return (
        <div className="flex flex-col lg:flex-row gap-8 h-[calc(100vh-180px)] relative">
            {/* Custom Toast Notification */}
            {toast.show && (
                <div className={`absolute top-4 right-4 z-50 flex items-center space-x-3 px-6 py-4 rounded-2xl shadow-2xl transition-all animate-in fade-in slide-in-from-top-5 duration-300 ${toast.type === 'success' ? 'bg-emerald-50 text-emerald-600 border border-emerald-200' : 'bg-red-50 text-red-600 border border-red-200'}`}>
                    <div className={`p-2 rounded-xl ${toast.type === 'success' ? 'bg-emerald-100' : 'bg-red-100'}`}>
                        {toast.type === 'success' ? <Check className="w-5 h-5" /> : <div className="w-5 h-5 flex justify-center items-center font-bold">!</div>}
                    </div>
                    <div>
                        <p className="font-bold text-[15px]">{toast.type === 'success' ? 'Success' : 'Error'}</p>
                        <p className="text-sm font-medium opacity-90">{toast.message}</p>
                    </div>
                </div>
            )}

            {/* Editor Section */}
            <div className="flex-1 bg-white rounded-[2.5rem] border border-slate-200 overflow-hidden flex flex-col shadow-xl shadow-slate-200/50">
                <div className="px-8 py-6 border-b border-slate-100 flex items-center justify-between bg-white">
                    <div className="flex items-center space-x-4">
                        <div className="w-12 h-12 bg-emerald-50 text-emerald-600 rounded-2xl flex items-center justify-center shadow-inner">
                            {view === 'LIST' ? <BookOpen className="w-6 h-6" /> : <SquarePen className="w-6 h-6" />}
                        </div>
                        <div>
                            <h2 className="text-xl font-black text-slate-800 tracking-tight">Lesson Notebook</h2>
                            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{view === 'LIST' ? 'Saved Notes' : 'Drafting Phase'}</p>
                        </div>
                    </div>
                    <div className="flex space-x-3">
                        {view === 'CREATE' ? (
                            <>
                                <button
                                    onClick={() => setView('LIST')}
                                    className="px-6 py-3 rounded-2xl font-bold transition-all text-slate-600 bg-slate-100 hover:bg-slate-200"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleSaveNote}
                                    className="flex items-center space-x-2 bg-slate-900 hover:bg-black text-white px-6 py-3 rounded-2xl font-bold transition-all shadow-lg shadow-slate-900/20 active:scale-95"
                                >
                                    <Save className="w-4 h-4" />
                                    <span>{currentNote.id ? "Update Note" : "Save to Library"}</span>
                                </button>
                            </>
                        ) : (
                            <button
                                onClick={() => {
                                    setCurrentNote({ subject: teacherData.subjects[0] || "", class: teacherData.classes[0] || "", topic: "", content: "" });
                                    setView('CREATE');
                                }}
                                className="flex items-center space-x-2 bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-3 rounded-2xl font-bold transition-all shadow-lg shadow-emerald-600/20 active:scale-95"
                            >
                                <Plus className="w-4 h-4" />
                                <span>Create New</span>
                            </button>
                        )}
                    </div>
                </div>

                {view === 'CREATE' ? (
                    <div className="p-10 flex-1 overflow-y-auto space-y-8 scrollbar-hide">
                        <div className="grid grid-cols-2 gap-8">
                            <div className="space-y-3">
                                <label className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Subject</label>
                                <select
                                    className="w-full bg-slate-50 border-2 border-transparent focus:border-emerald-500/20 focus:bg-white rounded-[1.25rem] px-6 py-4 outline-none transition-all font-bold text-slate-700 appearance-none cursor-pointer"
                                    value={currentNote.subject}
                                    onChange={(e) => setCurrentNote({ ...currentNote, subject: e.target.value })}
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
                                    className="w-full bg-slate-50 border-2 border-transparent focus:border-emerald-500/20 focus:bg-white rounded-[1.25rem] px-6 py-4 outline-none transition-all font-bold text-slate-700 appearance-none cursor-pointer"
                                    value={currentNote.class}
                                    onChange={(e) => setCurrentNote({ ...currentNote, class: e.target.value })}
                                >
                                    <option value="">Select Class</option>
                                    {teacherData.classes.map((cls, i) => (
                                        <option key={i} value={cls}>{cls}</option>
                                    ))}
                                </select>
                            </div>
                        </div>

                        <div className="space-y-3">
                            <label className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Lesson Topic</label>
                            <input
                                type="text"
                                placeholder="Enter the main title..."
                                className="w-full bg-slate-50 border-2 border-transparent focus:border-emerald-500/20 focus:bg-white rounded-[1.25rem] px-8 py-5 text-2xl font-black text-slate-800 outline-none transition-all placeholder:text-slate-300"
                                value={currentNote.topic}
                                onChange={(e) => setCurrentNote({ ...currentNote, topic: e.target.value })}
                            />
                        </div>

                        <div className="space-y-3 flex-1 flex flex-col">
                            <label className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Lesson Content</label>
                            <div className="bg-slate-50 border-2 border-transparent focus-within:border-emerald-500/20 focus-within:bg-white rounded-[2rem] overflow-hidden transition-all flex-1 flex flex-col min-h-[400px]">
                                <ReactQuill
                                    theme="snow"
                                    value={currentNote.content}
                                    onChange={(val: string) => setCurrentNote({ ...currentNote, content: val })}
                                    placeholder="Start writing the core substance of your lesson..."
                                    className="font-medium text-slate-700 leading-relaxed text-lg flex-1 flex flex-col"
                                />
                            </div>
                            <style jsx global>{`
                            .ql-toolbar.ql-snow {
                                border: none !important;
                                background: #f8fafc;
                                padding: 16px 24px !important;
                                border-bottom: 2px solid transparent !important;
                            }
                            .ql-container.ql-snow {
                                border: none !important;
                                flex: 1;
                                font-size: 1.125rem !important;
                            }
                            .ql-editor {
                                padding: 32px !important;
                                min-height: 300px;
                            }
                            .ql-editor.ql-blank::before {
                                left: 32px !important;
                                color: #cbd5e1 !important;
                                font-style: normal !important;
                            }
                        `}</style>
                        </div>
                    </div>
                ) : (
                    <div className="p-10 flex-1 overflow-y-auto">
                        {savedNotes.length === 0 ? (
                            <div className="flex flex-col items-center justify-center h-full text-center space-y-4">
                                <div className="w-16 h-16 bg-slate-100 rounded-2xl flex items-center justify-center text-slate-400">
                                    <BookOpen className="w-8 h-8" />
                                </div>
                                <div>
                                    <h3 className="text-lg font-bold text-slate-800">No Lesson Notes Yet</h3>
                                    <p className="text-sm text-slate-500 max-w-sm mx-auto mt-2">Create your first lesson note using the AI assistant or from scratch.</p>
                                </div>
                                <button
                                    onClick={() => setView('CREATE')}
                                    className="mt-4 px-6 py-3 bg-emerald-50 text-emerald-600 font-bold rounded-xl hover:bg-emerald-100 transition-colors"
                                >
                                    Create Note
                                </button>
                            </div>
                        ) : (
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-6">
                                {savedNotes.map((note) => (
                                    <div key={note.id} className="bg-white border-2 border-slate-100 rounded-[1.5rem] p-6 hover:border-emerald-500/30 transition-all group flex flex-col">
                                        <div className="flex justify-between items-start mb-4">
                                            <div>
                                                <span className="inline-block px-3 py-1 bg-emerald-50 text-emerald-600 rounded-lg text-xs font-bold mb-2">
                                                    {note.subject}
                                                </span>
                                                <span className="inline-block px-3 py-1 bg-blue-50 text-blue-600 rounded-lg text-xs font-bold mb-2 ml-2">
                                                    Class {note.class}
                                                </span>
                                            </div>
                                        </div>
                                        <h3 className="text-lg font-black text-slate-800 mb-2 truncate">{note.topic}</h3>
                                        <div className="text-sm text-slate-500 line-clamp-3 mb-6 flex-1" dangerouslySetInnerHTML={{ __html: note.content || '' }} />

                                        <div className="flex items-center space-x-3 pt-4 border-t border-slate-100 mt-auto">
                                            <button
                                                onClick={() => handleEditNote(note)}
                                                className="flex-1 py-2.5 bg-slate-50 hover:bg-slate-100 text-slate-700 font-bold rounded-xl transition-colors text-sm"
                                            >
                                                Edit Note
                                            </button>
                                            <button
                                                onClick={() => handleDeleteNote(note.id!)}
                                                className="px-4 py-2.5 bg-red-50 hover:bg-red-100 text-red-600 font-bold rounded-xl transition-colors text-sm"
                                            >
                                                Delete
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* Premium AI Assistant Sidebar */}
            <div className="w-full lg:w-[480px] bg-slate-950 rounded-[2.5rem] overflow-hidden flex flex-col shadow-2xl shadow-slate-900/40 border border-white/5">
                {/* AI Header */}
                <div className="p-6 border-b border-white/5 bg-slate-900/50 backdrop-blur-xl flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                        <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-emerald-500 rounded-2xl flex items-center justify-center text-white shadow-lg shadow-emerald-500/20 ring-4 ring-white/5">
                            <Sparkles className="w-6 h-6" />
                        </div>
                        <div>
                            <div className="flex items-center space-x-2">
                                <h3 className="text-white font-black tracking-tight">Jesa AI</h3>
                                <div className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 text-[8px] font-black uppercase tracking-widest rounded-full border border-emerald-500/20">Pro</div>
                            </div>
                            <select
                                value={model}
                                onChange={(e) => setModel(e.target.value)}
                                className="bg-transparent text-[10px] text-slate-400 font-bold outline-none cursor-pointer hover:text-slate-200 transition-colors"
                            >
                                <option className="bg-slate-900" value="GPT-4o">GPT-4o (Smartest)</option>
                                <option className="bg-slate-900" value="GPT-4o-mini">GPT-4o Mini (Fastest)</option>
                                <option className="bg-slate-900" value="o1">o1 (Deep Reasoning)</option>
                            </select>
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
                                        <div className="w-5 h-5 bg-emerald-500/20 rounded flex items-center justify-center">
                                            <Cpu className="w-3 h-3 text-emerald-400" />
                                        </div>
                                        <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Assistant</span>
                                    </div>
                                ) : (
                                    <div className="flex items-center space-x-2">
                                        <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">You</span>
                                        <div className="w-5 h-5 bg-indigo-500/20 rounded flex items-center justify-center">
                                            <User className="w-3 h-3 text-indigo-400" />
                                        </div>
                                    </div>
                                )}
                            </div>
                            <div className={`group relative max-w-[90%] rounded-[1.5rem] px-6 py-4 text-[15px] leading-relaxed transition-all ${msg.role === 'user'
                                ? 'bg-indigo-600 text-white rounded-tr-none shadow-lg shadow-indigo-600/10'
                                : 'bg-slate-900 text-slate-200 rounded-tl-none border border-white/5 hover:border-white/10'
                                }`}>
                                <div className="whitespace-pre-wrap">{msg.content}</div>

                                {msg.role === 'assistant' && i !== 0 && (
                                    <div className="mt-6 flex items-center space-x-3 pt-4 border-t border-white/5">
                                        <button
                                            onClick={() => applyToNote(msg.content)}
                                            className="flex items-center space-x-2 text-[10px] font-black uppercase tracking-[0.15em] bg-emerald-500 hover:bg-emerald-400 text-emerald-950 px-4 py-2 rounded-xl transition-all active:scale-95"
                                        >
                                            {copied ? <Check className="w-3 h-3" /> : <Plus className="w-3 h-3" />}
                                            <span>Apply to Note</span>
                                        </button>
                                        <button className="p-2 bg-white/5 hover:bg-white/10 rounded-xl transition-all text-slate-400 hover:text-white">
                                            <Copy className="w-3 h-3" />
                                        </button>
                                    </div>
                                )}
                            </div>
                        </div>
                    ))}
                    {isLoading && (
                        <div className="flex items-start flex-col space-y-2">
                            <div className="flex items-center space-x-2 px-1">
                                <div className="w-5 h-5 bg-emerald-500/20 rounded flex items-center justify-center">
                                    <Cpu className="w-3 h-3 text-emerald-400" />
                                </div>
                                <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Thinking...</span>
                            </div>
                            <div className="bg-slate-900 rounded-[1.5rem] rounded-tl-none p-6 border border-white/5 flex space-x-2">
                                <div className="w-2 h-2 bg-emerald-500 rounded-full animate-bounce [animation-delay:-0.3s]"></div>
                                <div className="w-2 h-2 bg-emerald-500 rounded-full animate-bounce [animation-delay:-0.15s]"></div>
                                <div className="w-2 h-2 bg-emerald-500 rounded-full animate-bounce"></div>
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
                            placeholder="Message Jesa AI..."
                            className="w-full bg-slate-800/50 border-2 border-white/5 rounded-[1.5rem] pl-6 pr-16 py-5 text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500/50 focus:bg-slate-800 transition-all font-medium text-base resize-none overflow-hidden"
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter' && !e.shiftKey) {
                                    e.preventDefault();
                                    handleSendMessage();
                                }
                            }}
                        />
                        <button
                            onClick={handleSendMessage}
                            disabled={isLoading || !input.trim()}
                            className="absolute right-3 top-3 p-3 bg-white text-slate-900 hover:bg-emerald-400 disabled:opacity-20 disabled:hover:bg-white transition-all rounded-xl shadow-xl active:scale-90 flex items-center justify-center"
                        >
                            <Send className="w-5 h-5 translate-x-0.5 -translate-y-0.5" />
                        </button>
                    </div>
                    <div className="mt-4 flex items-center justify-between px-2">
                        <div className="flex items-center space-x-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                            <Zap className="w-3 h-3 text-emerald-500" />
                            <span>System Status: Online</span>
                        </div>
                        <p className="text-[9px] text-slate-600 font-medium">Shift + Enter for new line</p>
                    </div>
                </div>
            </div>
        </div>
    );
}
