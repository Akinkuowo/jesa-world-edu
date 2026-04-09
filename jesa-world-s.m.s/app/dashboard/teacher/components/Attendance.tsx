"use client";

import { useState, useEffect } from "react";
import toast from "react-hot-toast";
import {
    Users,
    Search,
    Calendar,
    CheckCircle2,
    XCircle,
    Clock,
    Loader2,
    Save,
    Filter
} from "lucide-react";

export default function AttendanceView() {
    const [students, setStudents] = useState<any[]>([]);
    const [teacherSubjects, setTeacherSubjects] = useState<string[]>([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [selectedDate, setSelectedDate] = useState(new Date().toISOString().split('T')[0]);
    const [selectedClass, setSelectedClass] = useState("");
    const [searchTerm, setSearchTerm] = useState("");
    const [attendanceMap, setAttendanceMap] = useState<Record<string, 'PRESENT' | 'ABSENT' | 'LATE'>>({});

    const fetchStudents = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/students`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = await res.json();
            if (res.ok) {
                setStudents(data.students || []);
                setTeacherSubjects(data.teacherSubjects || []);
                
                // Set default class if available
                const classes = [...new Set(data.students.map((s: any) => s.studentClass))] as string[];
                if (classes.length > 0 && !selectedClass) {
                    setSelectedClass(classes[0]);
                }
            }
        } catch (err) {
            console.error(err);
            toast.error("Failed to fetch students");
        } finally {
            setLoading(false);
        }
    };

    const fetchExistingAttendance = async (date: string, className: string) => {
        if (!date || !className) return;
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/attendance?date=${date}&studentClass=${className}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = await res.json();
            if (res.ok) {
                const map: Record<string, 'PRESENT' | 'ABSENT' | 'LATE'> = {};
                data.forEach((record: any) => {
                    map[record.studentId] = record.status;
                });
                setAttendanceMap(map);
            }
        } catch (err) {
            console.error("Failed to fetch existing attendance", err);
        }
    };

    useEffect(() => {
        fetchStudents();
    }, []);

    useEffect(() => {
        if (selectedClass) {
            fetchExistingAttendance(selectedDate, selectedClass);
        }
    }, [selectedDate, selectedClass]);

    const handleMark = (studentId: string, status: 'PRESENT' | 'ABSENT' | 'LATE') => {
        setAttendanceMap(prev => ({
            ...prev,
            [studentId]: status
        }));
    };

    const handleMarkAll = (status: 'PRESENT' | 'ABSENT' | 'LATE') => {
        const newMap = { ...attendanceMap };
        filteredStudents.forEach(s => {
            newMap[s.id] = status;
        });
        setAttendanceMap(newMap);
    };

    const handleSubmit = async () => {
        if (!selectedClass) {
            toast.error("Please select a class");
            return;
        }

        const data = filteredStudents.map(s => ({
            studentId: s.id,
            status: attendanceMap[s.id] || 'PRESENT' // Default to present if not marked
        }));

        setSaving(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/attendance`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    date: selectedDate,
                    studentClass: selectedClass,
                    attendanceData: data
                })
            });

            if (res.ok) {
                toast.success("Attendance marked successfully!");
            } else {
                toast.error("Failed to save attendance");
            }
        } catch (err) {
            toast.error("Network error");
        } finally {
            setSaving(false);
        }
    };

    const studentClasses = [...new Set(students.map(s => s.studentClass))] as string[];
    
    const filteredStudents = students.filter(s => 
        (selectedClass ? s.studentClass === selectedClass : true) &&
        (s.firstName + " " + s.lastName).toLowerCase().includes(searchTerm.toLowerCase())
    );

    if (loading && students.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center p-20 text-slate-400">
                <Loader2 className="w-10 h-10 animate-spin mb-4" />
                <p className="font-bold">Loading students...</p>
            </div>
        );
    }

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Control Bar */}
            <div className="bg-white p-8 rounded-[2rem] border border-slate-200 shadow-sm">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                    <div className="flex flex-wrap items-center gap-4">
                        <div className="relative">
                            <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                            <input
                                type="date"
                                value={selectedDate}
                                onChange={(e) => setSelectedDate(e.target.value)}
                                className="pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                            />
                        </div>
                        <div className="relative">
                            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                            <select
                                value={selectedClass}
                                onChange={(e) => setSelectedClass(e.target.value)}
                                className="pl-10 pr-8 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:outline-none focus:ring-2 focus:ring-emerald-500/20 appearance-none cursor-pointer"
                            >
                                <option value="">Select Class</option>
                                {studentClasses.map(c => (
                                    <option key={c} value={c}>{c}</option>
                                ))}
                            </select>
                        </div>
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                            <input
                                type="text"
                                placeholder="Search student..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:outline-none focus:ring-2 focus:ring-emerald-500/20 w-64"
                            />
                        </div>
                    </div>

                    <div className="flex items-center space-x-3">
                        <div className="flex bg-slate-100 p-1 rounded-xl">
                            <button onClick={() => handleMarkAll('PRESENT')} className="px-3 py-1.5 text-[10px] font-black uppercase text-emerald-600 hover:bg-white rounded-lg transition-all">All Present</button>
                            <button onClick={() => handleMarkAll('ABSENT')} className="px-3 py-1.5 text-[10px] font-black uppercase text-red-600 hover:bg-white rounded-lg transition-all">All Absent</button>
                        </div>
                        <button 
                            onClick={handleSubmit}
                            disabled={saving || filteredStudents.length === 0}
                            className="flex items-center space-x-2 bg-emerald-600 text-white py-2.5 px-6 rounded-xl text-sm font-black hover:bg-emerald-700 transition-all shadow-lg shadow-emerald-600/20 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                            <span>Save Attendance</span>
                        </button>
                    </div>
                </div>

                {filteredStudents.length > 0 ? (
                    <div className="mt-8 overflow-x-auto">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="border-b border-slate-100">
                                    <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">Student Name</th>
                                    <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest text-center">Mark Status</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-50">
                                {filteredStudents.map((student) => (
                                    <tr key={student.id} className="group hover:bg-slate-50/50 transition-colors">
                                        <td className="py-4">
                                            <div className="flex items-center space-x-3">
                                                <div className="w-10 h-10 bg-slate-100 text-slate-500 rounded-xl flex items-center justify-center font-black text-sm border-2 border-white shadow-sm">
                                                    {student.firstName.charAt(0)}{student.lastName.charAt(0)}
                                                </div>
                                                <div>
                                                    <span className="font-black text-slate-900 text-sm block leading-none mb-1">{student.firstName} {student.lastName}</span>
                                                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{student.studentId}</span>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="py-4">
                                            <div className="flex items-center justify-center space-x-2">
                                                <AttendanceButton 
                                                    active={attendanceMap[student.id] === 'PRESENT'} 
                                                    onClick={() => handleMark(student.id, 'PRESENT')}
                                                    label="Present"
                                                    color="emerald"
                                                    icon={<CheckCircle2 className="w-3.5 h-3.5" />}
                                                />
                                                <AttendanceButton 
                                                    active={attendanceMap[student.id] === 'LATE'} 
                                                    onClick={() => handleMark(student.id, 'LATE')}
                                                    label="Late"
                                                    color="amber"
                                                    icon={<Clock className="w-3.5 h-3.5" />}
                                                />
                                                <AttendanceButton 
                                                    active={attendanceMap[student.id] === 'ABSENT'} 
                                                    onClick={() => handleMark(student.id, 'ABSENT')}
                                                    label="Absent"
                                                    color="red"
                                                    icon={<XCircle className="w-3.5 h-3.5" />}
                                                />
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <div className="py-20 text-center">
                        <Users className="w-12 h-12 text-slate-100 mx-auto mb-4" />
                        <p className="text-slate-400 font-bold text-sm uppercase tracking-widest">No students found for this class</p>
                    </div>
                )}
            </div>
        </div>
    );
}

function AttendanceButton({ active, onClick, label, color, icon }: { active: boolean, onClick: () => void, label: string, color: string, icon: any }) {
    const activeClasses: any = {
        emerald: "bg-emerald-600 text-white shadow-lg shadow-emerald-500/20 border-emerald-600",
        amber: "bg-amber-500 text-white shadow-lg shadow-amber-500/20 border-amber-500",
        red: "bg-red-500 text-white shadow-lg shadow-red-500/20 border-red-500"
    };

    const inactiveClasses: any = {
        emerald: "text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 hover:border-emerald-100",
        amber: "text-slate-400 hover:text-amber-600 hover:bg-amber-50 hover:border-amber-100",
        red: "text-slate-400 hover:text-red-600 hover:bg-red-50 hover:border-red-100"
    };

    return (
        <button
            onClick={onClick}
            className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest border transition-all ${
                active ? activeClasses[color] : `bg-white border-slate-200 ${inactiveClasses[color]}`
            }`}
        >
            {icon}
            <span>{label}</span>
        </button>
    );
}
