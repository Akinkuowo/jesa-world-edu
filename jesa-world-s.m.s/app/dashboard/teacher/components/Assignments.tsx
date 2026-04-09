"use client";

import { useState, useEffect } from "react";
import {
    Plus,
    Calendar,
    Book,
    Users,
    Clock,
    FileText,
    ChevronRight,
    Search,
    Loader2,
    User,
    ArrowLeft
} from "lucide-react";

export default function Assignments() {
    const [view, setView] = useState<'LIST' | 'CREATE' | 'SUBMISSIONS'>('LIST');
    const [viewingAssignment, setViewingAssignment] = useState<any>(null);
    const [submissions, setSubmissions] = useState<any[]>([]);
    const [loadingSubmissions, setLoadingSubmissions] = useState(false);
    const [newAssignment, setNewAssignment] = useState({
        title: "",
        subject: "",
        class: "",
        dueDate: "",
        description: ""
    });
    const [teacherData, setTeacherData] = useState<{ subjects: string[]; classes: string[] }>({ subjects: [], classes: [] });
    const [loadingData, setLoadingData] = useState(false);
    const [assignments, setAssignments] = useState<any[]>([]);
    const [loadingAssignments, setLoadingAssignments] = useState(false);

    const fetchAssignments = async () => {
        setLoadingAssignments(true);
        try {
            const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/assignments`, {
                headers: {
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                }
            });
            if (response.ok) {
                setAssignments(await response.json());
            }
        } catch (error) {
            console.error("Fetch assignments error:", error);
        } finally {
            setLoadingAssignments(false);
        }
    };

    const fetchSubmissions = async (assignment: any) => {
        setViewingAssignment(assignment);
        setView('SUBMISSIONS');
        setLoadingSubmissions(true);
        try {
            const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/assignments/${assignment.id}/submissions`, {
                headers: {
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                }
            });
            if (response.ok) {
                setSubmissions(await response.json());
            }
        } catch (error) {
            console.error("Fetch submissions error:", error);
        } finally {
            setLoadingSubmissions(false);
        }
    };

    useEffect(() => {
        const fetchTeacherData = async () => {
            setLoadingData(true);
            try {
                const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/my-data`, {
                    headers: {
                        "Authorization": `Bearer ${localStorage.getItem("token")}`
                    }
                });
                if (response.ok) {
                    const data = await response.json();
                    setTeacherData(data);
                    // Pre-select first values if available
                    if (data.subjects.length > 0) setNewAssignment(prev => ({ ...prev, subject: data.subjects[0] }));
                    if (data.classes.length > 0) setNewAssignment(prev => ({ ...prev, class: data.classes[0] }));
                }
            } catch (error) {
                console.error("Fetch error:", error);
            } finally {
                setLoadingData(false);
            }
        };

        fetchTeacherData();
        fetchAssignments();
    }, []);

    const handleCreate = async () => {
        try {
            const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/assignments`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                },
                body: JSON.stringify(newAssignment)
            });

            if (response.ok) {
                alert("Assignment created successfully!");
                fetchAssignments();
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
                loadingAssignments ? (
                    <div className="flex flex-col items-center justify-center p-20 text-slate-400">
                        <Loader2 className="w-10 h-10 animate-spin mb-4 text-emerald-500" />
                        <p className="font-bold">Fetching assignments...</p>
                    </div>
                ) : assignments.length === 0 ? (
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
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {assignments.map((assignment) => (
                            <div key={assignment.id} className="bg-white rounded-3xl border border-slate-200 p-6 shadow-sm hover:shadow-md transition-all group">
                                <div className="flex items-start justify-between mb-4">
                                    <div className="w-12 h-12 bg-emerald-50 rounded-2xl flex items-center justify-center text-emerald-600 group-hover:scale-110 transition-transform">
                                        <FileText className="w-6 h-6" />
                                    </div>
                                    <span className="text-[10px] font-black uppercase tracking-wider bg-slate-100 px-3 py-1 rounded-full text-slate-500">
                                        {assignment.class}
                                    </span>
                                </div>
                                <h3 className="text-lg font-bold text-slate-800 mb-2">{assignment.title}</h3>
                                <p className="text-sm text-slate-500 line-clamp-2 mb-6 font-medium">{assignment.description}</p>
                                
                                <div className="flex items-center justify-between pt-4 border-t border-slate-50">
                                    <div className="flex items-center space-x-2">
                                        <div className="w-8 h-8 bg-indigo-50 rounded-lg flex items-center justify-center text-indigo-500">
                                            <Calendar className="w-4 h-4" />
                                        </div>
                                        <span className="text-xs font-bold text-slate-500">
                                            Due {new Date(assignment.dueDate).toLocaleDateString()}
                                        </span>
                                    </div>
                                    <button 
                                        onClick={() => fetchSubmissions(assignment)}
                                        className="text-xs font-black text-emerald-600 uppercase tracking-widest hover:underline"
                                    >
                                        View Submissions
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )
            ) : view === 'CREATE' ? (
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
                                <select
                                    disabled={loadingData}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all font-medium appearance-none"
                                    value={newAssignment.subject}
                                    onChange={(e) => setNewAssignment({ ...newAssignment, subject: e.target.value })}
                                >
                                    {loadingData ? (
                                        <option>Loading subjects...</option>
                                    ) : teacherData.subjects.length > 0 ? (
                                        teacherData.subjects.map(s => <option key={s} value={s}>{s}</option>)
                                    ) : (
                                        <option value="">No subjects found</option>
                                    )}
                                </select>
                            </div>
                            <div className="space-y-2">
                                <label className="text-xs font-bold text-slate-400 uppercase tracking-widest ml-1">Target Class</label>
                                <select
                                    disabled={loadingData}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all font-medium appearance-none"
                                    value={newAssignment.class}
                                    onChange={(e) => setNewAssignment({ ...newAssignment, class: e.target.value })}
                                >
                                    {loadingData ? (
                                        <option>Loading classes...</option>
                                    ) : teacherData.classes.length > 0 ? (
                                        teacherData.classes.map(c => <option key={c} value={c}>{c}</option>)
                                    ) : (
                                        <option value="">No classes found</option>
                                    )}
                                </select>
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
            ) : (
                <div className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm">
                    <button 
                        onClick={() => setView('LIST')}
                        className="flex items-center space-x-2 text-slate-400 hover:text-slate-800 font-bold text-sm mb-8 transition-colors"
                    >
                        <ArrowLeft className="w-4 h-4" />
                        <span>Back to assignments</span>
                    </button>

                    <div className="mb-8">
                        <h2 className="text-2xl font-black text-slate-900">{viewingAssignment?.title}</h2>
                        <div className="flex items-center space-x-3 mt-2">
                            <span className="text-[10px] font-black uppercase tracking-wider bg-slate-100 px-3 py-1 rounded-full text-slate-500">{viewingAssignment?.class}</span>
                            <span className="text-[10px] font-black uppercase tracking-wider bg-emerald-50 px-3 py-1 rounded-full text-emerald-600">{viewingAssignment?.subject}</span>
                        </div>
                    </div>

                    {loadingSubmissions ? (
                        <div className="flex flex-col items-center justify-center py-20 text-slate-400">
                            <Loader2 className="w-10 h-10 animate-spin mb-4 text-emerald-500" />
                            <p className="font-bold">Loading submissions...</p>
                        </div>
                    ) : submissions.length === 0 ? (
                        <div className="text-center py-20 border-2 border-dashed border-slate-100 rounded-3xl">
                            <Users className="w-12 h-12 text-slate-200 mx-auto mb-4" />
                            <p className="text-slate-400 font-bold uppercase tracking-widest text-sm">No submissions yet</p>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="border-b border-slate-100">
                                        <th className="text-left py-4 px-2 text-[10px] font-black text-slate-400 uppercase tracking-widest">Student</th>
                                        <th className="text-left py-4 px-2 text-[10px] font-black text-slate-400 uppercase tracking-widest">Student ID</th>
                                        <th className="text-left py-4 px-2 text-[10px] font-black text-slate-400 uppercase tracking-widest">Date Submitted</th>
                                        <th className="text-left py-4 px-2 text-[10px] font-black text-slate-400 uppercase tracking-widest">Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {submissions.map((sub) => (
                                        <tr key={sub.id} className="border-b border-slate-50 hover:bg-slate-50/50 transition-colors group">
                                            <td className="py-4 px-2 text-sm font-bold text-slate-800">
                                                <div className="flex items-center space-x-3">
                                                    <div className="w-8 h-8 rounded-lg bg-indigo-50 flex items-center justify-center text-indigo-600">
                                                        <User className="w-4 h-4" />
                                                    </div>
                                                    <span>{sub.student.firstName} {sub.student.lastName}</span>
                                                </div>
                                            </td>
                                            <td className="py-4 px-2 text-sm font-bold text-slate-500 uppercase">{sub.student.studentId}</td>
                                            <td className="py-4 px-2 text-sm font-bold text-slate-500">{new Date(sub.submittedAt).toLocaleString()}</td>
                                            <td className="py-4 px-2">
                                                <button className="text-[10px] font-black text-emerald-600 uppercase tracking-widest bg-emerald-50 px-3 py-1.5 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity">
                                                    View content
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
