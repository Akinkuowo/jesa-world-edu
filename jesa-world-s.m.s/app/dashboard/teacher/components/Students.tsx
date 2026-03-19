"use client";

import { useState, useEffect } from "react";
import {
    Users,
    Search,
    BookOpen,
    Mail,
    Phone,
    MapPin,
    Loader2,
    Filter,
    GraduationCap
} from "lucide-react";

export default function StudentsView() {
    const [students, setStudents] = useState<any[]>([]);
    const [teacherSubjects, setTeacherSubjects] = useState<string[]>([]);
    const [loading, setLoading] = useState(true);
    const [filterSubject, setFilterSubject] = useState("");
    const [searchTerm, setSearchTerm] = useState("");

    const fetchStudents = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const url = new URL(`${process.env.NEXT_PUBLIC_API_URL}/teacher/students`);
            if (filterSubject) url.searchParams.append("subject", filterSubject);

            const res = await fetch(url.toString(), {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = await res.json();
            if (res.ok) {
                setStudents(data.students || []);
                setTeacherSubjects(data.teacherSubjects || []);
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStudents();
    }, [filterSubject]);

    const filteredStudents = students.filter(s =>
        (s.firstName + " " + s.lastName + " " + s.studentId).toLowerCase().includes(searchTerm.toLowerCase())
    );

    if (loading && students.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center p-20 text-slate-400">
                <Loader2 className="w-10 h-10 animate-spin mb-4" />
                <p className="font-bold">Loading your students...</p>
            </div>
        );
    }

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Filter Bar */}
            <div className="bg-white p-6 rounded-[2rem] border border-slate-200 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex flex-1 items-center space-x-4">
                    <div className="relative flex-1 max-w-md">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                        <input
                            type="text"
                            placeholder="Search by name or ID..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full pl-12 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl text-sm font-medium focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                        />
                    </div>
                    <div className="relative">
                        <Filter className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-emerald-600" />
                        <select
                            value={filterSubject}
                            onChange={(e) => setFilterSubject(e.target.value)}
                            className="pl-12 pr-8 py-3 bg-emerald-50/50 border border-emerald-100 rounded-2xl text-sm font-bold text-emerald-900 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 appearance-none cursor-pointer"
                        >
                            <option value="">All My Subjects</option>
                            {teacherSubjects.map(sub => (
                                <option key={sub} value={sub}>{sub}</option>
                            ))}
                        </select>
                    </div>
                </div>
                <div className="text-xs font-bold text-slate-400 uppercase tracking-widest px-4">
                    {filteredStudents.length} Students found
                </div>
            </div>

            {/* Students Grid */}
            {filteredStudents.length === 0 ? (
                <div className="bg-white rounded-[2rem] border border-slate-200 p-20 text-center shadow-sm">
                    <div className="w-20 h-20 bg-slate-50 rounded-3xl flex items-center justify-center mx-auto mb-6 text-slate-200">
                        <Users className="w-10 h-10" />
                    </div>
                    <h3 className="text-xl font-black text-slate-900 mb-2">No Students Found</h3>
                    <p className="text-slate-500 font-medium max-w-sm mx-auto">Either you are not teaching any subjects yet, or no students offer your subjects.</p>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {filteredStudents.map(student => (
                        <div key={student.id} className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm group hover:border-emerald-200 transition-all relative overflow-hidden">
                            <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-50 rounded-bl-[4rem] -mr-8 -mt-8 opacity-0 group-hover:opacity-100 transition-opacity" />

                            <div className="flex items-start justify-between mb-6 relative">
                                <div className="flex items-center space-x-4">
                                    <div className="w-14 h-14 bg-slate-100 rounded-2xl flex items-center justify-center font-black text-slate-500 text-xl border-2 border-white shadow-sm">
                                        {student.firstName[0]}{student.lastName[0]}
                                    </div>
                                    <div>
                                        <h4 className="text-lg font-black text-slate-900 leading-none mb-1">{student.firstName} {student.lastName}</h4>
                                        <div className="flex items-center space-x-2">
                                            <span className="text-[10px] font-black text-emerald-600 uppercase tracking-widest">{student.studentClass}</span>
                                            <span className="w-1 h-1 bg-slate-300 rounded-full" />
                                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{student.studentId}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-4 relative">
                                <div className="flex items-center space-x-3 text-slate-500 text-xs font-medium">
                                    <Mail className="w-4 h-4 text-slate-300" />
                                    <span className="truncate">{student.email}</span>
                                </div>
                                <div className="flex items-center space-x-3 text-slate-500 text-xs font-medium">
                                    <Phone className="w-4 h-4 text-slate-300" />
                                    <span>{student.phone || "No phone listed"}</span>
                                </div>
                                <div className="pt-6 border-t border-slate-100">
                                    <p className="text-[9px] font-black text-slate-400 uppercase tracking-[0.2em] mb-3">Subjects Offered</p>
                                    <div className="flex flex-wrap gap-2">
                                        {student.subjects.slice(0, 3).map((sub: string) => (
                                            <span key={sub} className={`px-3 py-1 rounded-lg text-[10px] font-black uppercase ${teacherSubjects.includes(sub) ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-50 text-slate-500'}`}>
                                                {sub}
                                            </span>
                                        ))}
                                        {student.subjects.length > 3 && (
                                            <span className="px-3 py-1 bg-slate-50 text-slate-400 rounded-lg text-[10px] font-black uppercase">+{student.subjects.length - 3} More</span>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
