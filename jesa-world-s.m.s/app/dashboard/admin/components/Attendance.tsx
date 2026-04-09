"use client";

import { useState } from "react";
import {
    Search,
    Calendar,
    Filter,
    CheckCircle2,
    XCircle,
    Clock,
    MoreHorizontal,
    Download,
    Loader2
} from "lucide-react";
import { useEffect } from "react";

export default function Attendance() {
    const [selectedDate, setSelectedDate] = useState(new Date().toISOString().split('T')[0]);
    const [selectedClass, setSelectedClass] = useState("js1");
    const [searchTerm, setSearchTerm] = useState("");

    const [attendanceData, setAttendanceData] = useState<any[]>([]);
    const [stats, setStats] = useState({
        total: 0,
        present: 0,
        absent: 0,
        late: 0
    });
    const [loading, setLoading] = useState(true);

    const fetchAttendance = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/attendance?date=${selectedDate}&studentClass=${selectedClass}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = await res.json();
            if (res.ok) {
                setAttendanceData(data.attendanceData || []);
                setStats(data.stats || { total: 0, present: 0, absent: 0, late: 0 });
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useState(() => {
        fetchAttendance();
    });

    useEffect(() => {
        fetchAttendance();
    }, [selectedDate, selectedClass]);

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Header / Stats Summary */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <StatCard title="Total Students" value={stats.total} icon={<Search className="text-blue-600" />} color="blue" />
                <StatCard title="Present Today" value={stats.present} icon={<CheckCircle2 className="text-emerald-600" />} color="emerald" />
                <StatCard title="Absent" value={stats.absent} icon={<XCircle className="text-red-600" />} color="red" />
                <StatCard title="Late" value={stats.late} icon={<Clock className="text-amber-600" />} color="amber" />
            </div>

            {/* Filters and Controls */}
            <div className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                    <div className="flex flex-wrap items-center gap-4">
                        <div className="relative">
                            <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                            <input
                                type="date"
                                value={selectedDate}
                                onChange={(e) => setSelectedDate(e.target.value)}
                                className="pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                            />
                        </div>
                        <select
                            value={selectedClass}
                            onChange={(e) => setSelectedClass(e.target.value)}
                            className="px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                        >
                            <option value="js1">JS1</option>
                            <option value="js2">JS2</option>
                            <option value="js3">JS3</option>
                            <option value="ss1">SS1</option>
                            <option value="ss2">SS2</option>
                            <option value="ss3">SS3</option>
                        </select>
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                            <input
                                type="text"
                                placeholder="Search student name..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20 w-64"
                            />
                        </div>
                    </div>
                    <div className="flex items-center space-x-3">
                        <button className="flex items-center space-x-2 bg-slate-900 text-white py-2.5 px-6 rounded-xl text-sm font-bold hover:bg-slate-800 transition-all shadow-lg shadow-slate-900/20">
                            <Download className="w-4 h-4" />
                            <span>Export Report</span>
                        </button>
                    </div>
                </div>

                <div className="mt-8 overflow-x-auto min-h-[300px] relative">
                    {loading && (
                        <div className="absolute inset-0 bg-white/50 backdrop-blur-[1px] z-10 flex items-center justify-center">
                            <Loader2 className="w-8 h-8 animate-spin text-indigo-600" />
                        </div>
                    )}
                    <table className="w-full text-left">
                        <thead>
                            <tr className="border-b border-slate-100">
                                <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">Student Name</th>
                                <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">ID Number</th>
                                <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">Status</th>
                                <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">Marked Time</th>
                                <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-50">
                            {attendanceData.filter(s => s.name.toLowerCase().includes(searchTerm.toLowerCase())).map((student) => (
                                <tr key={student.id} className="group hover:bg-slate-50/50 transition-colors">
                                    <td className="py-4">
                                        <div className="flex items-center space-x-3">
                                            <div className="w-8 h-8 bg-indigo-50 text-indigo-600 rounded-full flex items-center justify-center font-bold text-xs">
                                                {student.name.charAt(0)}
                                            </div>
                                            <span className="font-bold text-slate-900 text-sm">{student.name}</span>
                                        </div>
                                    </td>
                                    <td className="py-4 text-xs font-mono text-slate-500">{student.id}</td>
                                    <td className="py-4">
                                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-black ${student.status === 'PRESENT' ? 'bg-emerald-50 text-emerald-600' :
                                                student.status === 'LATE' ? 'bg-amber-50 text-amber-600' :
                                                    student.status === 'ABSENT' ? 'bg-red-50 text-red-600' : 'bg-slate-50 text-slate-400'
                                            }`}>
                                            {student.status}
                                        </span>
                                    </td>
                                    <td className="py-4 text-xs font-bold text-slate-600">{student.time}</td>
                                    <td className="py-4 text-right">
                                        <button className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors">
                                            <MoreHorizontal className="w-4 h-4" />
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {!loading && attendanceData.length === 0 && (
                        <div className="text-center py-10">
                            <p className="text-sm font-bold text-slate-400">No students found for this class.</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

function StatCard({ title, value, icon, color }: { title: string, value: number, icon: any, color: string }) {
    const colorMap: any = {
        blue: "bg-blue-50 border-blue-100",
        emerald: "bg-emerald-50 border-emerald-100",
        red: "bg-red-50 border-red-100",
        amber: "bg-amber-50 border-amber-100",
    };

    return (
        <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm">
            <div className="flex items-center justify-between mb-4">
                <div className={`p-3 rounded-xl ${colorMap[color]}`}>{icon}</div>
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Today</span>
            </div>
            <h3 className="text-3xl font-black text-slate-900 mb-1">{value}</h3>
            <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">{title}</p>
        </div>
    );
}
