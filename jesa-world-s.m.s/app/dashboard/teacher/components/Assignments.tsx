"use client";

import { useState } from "react";
import {
    Plus,
    Calendar,
    Book,
    Users,
    Clock,
    FileText,
    ChevronRight,
    Search
} from "lucide-react";

export default function Assignments() {
    const [view, setView] = useState<'LIST' | 'CREATE'>('LIST');
    const [newAssignment, setNewAssignment] = useState({
        title: "",
        subject: "",
        class: "",
        dueDate: "",
        description: ""
    });

    const handleCreate = async () => {
        try {
            const response = await fetch("http://localhost:4000/api/teacher/assignments", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                },
                body: JSON.stringify(newAssignment)
            });

            if (response.ok) {
                alert("Assignment created successfully!");
                setView('LIST');
            }
        } catch (error) {
            console.error("Create error:", error);
        }
    };

    return (
        <div className="space-y-8">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-black text-slate-800">Class Assignments</h2>
                    <p className="text-slate-500 text-sm font-medium">Manage and track student assessments</p>
                </div>
                {view === 'LIST' ? (
                    <button
                        onClick={() => setView('CREATE')}
                        className="bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-3 rounded-2xl font-bold transition-all shadow-lg shadow-emerald-600/20 flex items-center space-x-2"
                    >
                        <Plus className="w-5 h-5" />
                        <span>New Assignment</span>
                    </button>
                ) : (
                    <button
                        onClick={() => setView('LIST')}
                        className="text-slate-500 hover:text-slate-800 font-bold text-sm px-4 py-2"
                    >
                        Cancel
                    </button>
                )}
            </div>

            {view === 'LIST' ? (
                <div className="grid grid-cols-1 gap-6">
                    <div className="bg-white rounded-[2rem] border border-slate-200 p-12 text-center space-y-4">
                        <div className="w-20 h-20 bg-slate-50 rounded-full flex items-center justify-center mx-auto mb-4">
                            <Book className="w-10 h-10 text-slate-300" />
                        </div>
                        <h3 className="text-xl font-bold text-slate-800">No Assignments Yet</h3>
                        <p className="text-slate-500 max-w-sm mx-auto">Create your first assignment to start tracking student progress.</p>
                        <button
                            onClick={() => setView('CREATE')}
                            className="text-emerald-600 font-bold hover:underline"
                        >
                            Get started now
                        </button>
                    </div>
                </div>
            ) : (
                <div className="bg-white rounded-3xl border border-slate-200 p-8 max-w-3xl mx-auto shadow-sm">
                    <div className="space-y-6">
                        <div className="space-y-2">
                            <label className="text-xs font-bold text-slate-400 uppercase tracking-widest ml-1">Title</label>
                            <input
                                type="text"
                                placeholder="e.g. Weekly Quiz on Algebra"
                                className="w-full bg-slate-50 border border-slate-200 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all font-medium"
                                value={newAssignment.title}
                                onChange={(e) => setNewAssignment({ ...newAssignment, title: e.target.value })}
                            />
                        </div>

                        <div className="grid grid-cols-2 gap-6">
                            <div className="space-y-2">
                                <label className="text-xs font-bold text-slate-400 uppercase tracking-widest ml-1">Subject</label>
                                <input
                                    type="text"
                                    placeholder="Mathematics"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all font-medium"
                                    value={newAssignment.subject}
                                    onChange={(e) => setNewAssignment({ ...newAssignment, subject: e.target.value })}
                                />
                            </div>
                            <div className="space-y-2">
                                <label className="text-xs font-bold text-slate-400 uppercase tracking-widest ml-1">Target Class</label>
                                <input
                                    type="text"
                                    placeholder="SSS 1"
                                    className="w-full bg-slate-50 border border-slate-200 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all font-medium"
                                    value={newAssignment.class}
                                    onChange={(e) => setNewAssignment({ ...newAssignment, class: e.target.value })}
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <label className="text-xs font-bold text-slate-400 uppercase tracking-widest ml-1">Due Date</label>
                            <input
                                type="date"
                                className="w-full bg-slate-50 border border-slate-200 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all font-medium"
                                value={newAssignment.dueDate}
                                onChange={(e) => setNewAssignment({ ...newAssignment, dueDate: e.target.value })}
                            />
                        </div>

                        <div className="space-y-2">
                            <label className="text-xs font-bold text-slate-400 uppercase tracking-widest ml-1">Description / Instructions</label>
                            <textarea
                                placeholder="Detail the assignment requirements here..."
                                className="w-full bg-slate-50 border border-slate-200 rounded-2xl px-6 py-4 min-h-[150px] focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all font-medium leading-relaxed"
                                value={newAssignment.description}
                                onChange={(e) => setNewAssignment({ ...newAssignment, description: e.target.value })}
                            />
                        </div>

                        <button
                            onClick={handleCreate}
                            className="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-4 rounded-2xl font-bold transition-all shadow-lg shadow-emerald-600/20"
                        >
                            Create Assignment
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}
