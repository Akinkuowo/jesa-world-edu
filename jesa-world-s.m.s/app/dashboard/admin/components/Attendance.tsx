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
    Download
} from "lucide-react";

export default function Attendance() {
    const [selectedDate, setSelectedDate] = useState(new Date().toISOString().split('T')[0]);
    const [selectedClass, setSelectedClass] = useState("js1");
    const [searchTerm, setSearchTerm] = useState("");

    // Mock data for demonstration
    const attendanceData = [
        { id: "S001", name: "John Doe", class: "JS1", status: "PRESENT", time: "07:45 AM" },
        { id: "S002", name: "Jane Smith", class: "JS1", status: "PRESENT", time: "07:50 AM" },
        { id: "S003", name: "Mike Johnson", class: "JS1", status: "LATE", time: "08:15 AM" },
        { id: "S004", name: "Sarah Williams", class: "JS1", status: "ABSENT", time: "-" },
        { id: "S005", name: "Robert Brown", class: "JS1", status: "PRESENT", time: "07:42 AM" },
    ];

    const stats = {
        total: 45,
        present: 38,
        absent: 4,
        late: 3
    };

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

                <div className="mt-8 overflow-x-auto">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="border-b border-slate-100">
                                <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">Student Name</th>
                                <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">ID Number</th>
                                <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">Status</th>
                                <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">Arrival Time</th>
                                <th className="pb-4 text-[10px] font-black text-slate-400 uppercase tracking-widest text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-50">
                            {attendanceData.map((student) => (
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
                                                    'bg-red-50 text-red-600'
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
