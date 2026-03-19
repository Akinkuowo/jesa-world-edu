"use client";

import { useState, useEffect } from "react";
import { User, BookOpen, Calendar, TrendingUp, Award, Clock, CheckCircle, XCircle, Bell, LogOut } from "lucide-react";
import { useRouter } from "next/navigation";

export default function ParentDashboard() {
    const router = useRouter();
    const [student, setStudent] = useState<any>(null);
    const [results, setResults] = useState<any[]>([]);
    const [gradingSystem, setGradingSystem] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchDashboardData = async () => {
            try {
                const token = localStorage.getItem("token");
                const user = JSON.parse(localStorage.getItem("user") || "{}");

                if (!token) {
                    router.push("/login");
                    return;
                }

                setStudent(user);

                // Fetch Academic Results
                const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/student/results`, {
                    headers: { Authorization: `Bearer ${token}` }
                });

                if (res.ok) {
                    const data = await res.json();
                    setResults(data.results || []);
                    setGradingSystem(data.grading || []);
                }
            } catch (error) {
                console.error("Failed to fetch dashboard data:", error);
            } finally {
                setLoading(false);
            }
        };

        fetchDashboardData();
    }, [router]);

    const getGrade = (score: number) => {
        if (!gradingSystem.length) return { grade: "--", remark: "--", color: "text-slate-400" };
        const grade = gradingSystem.find(g => score >= g.minScore);
        if (!grade) return { grade: "F", remark: "Fail", color: "text-red-400" };
        
        // Dynamic colors based on grade
        let color = "text-slate-400";
        if (grade.grade.startsWith('A')) color = "text-emerald-400";
        else if (grade.grade.startsWith('B')) color = "text-blue-400";
        else if (grade.grade.startsWith('C')) color = "text-amber-400";
        else if (grade.grade.startsWith('D') || grade.grade.startsWith('E')) color = "text-orange-400";
        else if (grade.grade === 'F') color = "text-red-400";

        return { grade: grade.grade, remark: grade.remark, color };
    };

    const handleLogout = () => {
        localStorage.removeItem("token");
        localStorage.removeItem("user");
        localStorage.removeItem("isParentMode");
        router.push("/login");
    };

    if (loading) {
        return (
            <div className="min-h-screen bg-[#0a0d14] flex items-center justify-center">
                <div className="flex flex-col items-center space-y-4">
                    <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
                    <span className="text-slate-400 font-medium">Loading child information...</span>
                </div>
            </div>
        );
    }

    const overallAvg = results.length > 0 
        ? Math.round(results.reduce((acc, r) => acc + r.marks, 0) / results.length)
        : 0;

    return (
        <div className="min-h-screen bg-[#0a0d14] text-white">
            {/* Header */}
            <header className="bg-[#11141b] border-b border-white/5 sticky top-0 z-50 backdrop-blur-xl">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4">
                            <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center">
                                <User className="w-6 h-6" />
                            </div>
                            <div>
                                <h1 className="text-xl font-bold">Parent Portal</h1>
                                <p className="text-sm text-slate-400">View your child's progress</p>
                            </div>
                        </div>
                        <button
                            onClick={handleLogout}
                            className="flex items-center space-x-2 px-4 py-2 bg-red-600/10 hover:bg-red-600/20 text-red-400 rounded-xl transition-all"
                        >
                            <LogOut className="w-4 h-4" />
                            <span className="text-sm font-medium">Logout</span>
                        </button>
                    </div>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                {/* Student Info Card */}
                <div className="bg-gradient-to-br from-blue-600 to-indigo-600 rounded-3xl p-8 mb-8 shadow-2xl">
                    <div className="flex items-center space-x-6">
                        <div className="w-20 h-20 bg-white/20 rounded-2xl flex items-center justify-center text-3xl font-bold backdrop-blur-sm">
                            {student?.firstName?.[0]}{student?.lastName?.[0]}
                        </div>
                        <div className="flex-1">
                            <h2 className="text-3xl font-bold mb-1">
                                {student?.firstName} {student?.lastName}
                            </h2>
                            <p className="text-blue-100 text-sm">
                                {student?.email}
                            </p>
                            <div className="flex items-center space-x-4 mt-3">
                                <div className="px-3 py-1 bg-white/20 rounded-full text-xs font-bold backdrop-blur-sm">
                                    Student ID: {student?.studentId || student?.id?.slice(0, 8).toUpperCase()}
                                </div>
                                <div className="px-3 py-1 bg-white/20 rounded-full text-xs font-bold backdrop-blur-sm capitalize">
                                    Class: {student?.studentClass || "N/A"}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    <div className="bg-[#11141b] rounded-2xl p-6 border border-white/5">
                        <div className="flex items-center justify-between mb-4">
                            <div className="w-12 h-12 bg-blue-600/10 rounded-xl flex items-center justify-center">
                                <TrendingUp className="w-6 h-6 text-blue-400" />
                            </div>
                            <span className="text-2xl font-bold text-blue-400">{overallAvg}%</span>
                        </div>
                        <h3 className="text-slate-400 text-sm font-medium">Overall Average</h3>
                        <p className="text-xs text-slate-600 mt-1">Based on {results.length} subjects</p>
                    </div>

                    <div className="bg-[#11141b] rounded-2xl p-6 border border-white/5">
                        <div className="flex items-center justify-between mb-4">
                            <div className="w-12 h-12 bg-emerald-600/10 rounded-xl flex items-center justify-center">
                                <Calendar className="w-6 h-6 text-emerald-400" />
                            </div>
                            <span className="text-2xl font-bold text-emerald-400">--</span>
                        </div>
                        <h3 className="text-slate-400 text-sm font-medium">Attendance Rate</h3>
                        <p className="text-xs text-slate-600 mt-1">Feature coming soon</p>
                    </div>

                    <div className="bg-[#11141b] rounded-2xl p-6 border border-white/5">
                        <div className="flex items-center justify-between mb-4">
                            <div className="w-12 h-12 bg-amber-600/10 rounded-xl flex items-center justify-center">
                                <BookOpen className="w-6 h-6 text-amber-400" />
                            </div>
                            <span className="text-2xl font-bold text-amber-400">{results.length}</span>
                        </div>
                        <h3 className="text-slate-400 text-sm font-medium">Subjects Taken</h3>
                        <p className="text-xs text-slate-600 mt-1">Current term</p>
                    </div>

                    <div className="bg-[#11141b] rounded-2xl p-6 border border-white/5">
                        <div className="flex items-center justify-between mb-4">
                            <div className="w-12 h-12 bg-purple-600/10 rounded-xl flex items-center justify-center">
                                <Award className="w-6 h-6 text-purple-400" />
                            </div>
                            <span className="text-2xl font-bold text-purple-400">--</span>
                        </div>
                        <h3 className="text-slate-400 text-sm font-medium">Achievements</h3>
                        <p className="text-xs text-slate-600 mt-1">Badges and honors</p>
                    </div>
                </div>

                {/* Main Content Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    {/* Academic Results */}
                    <div className="lg:col-span-2 bg-[#11141b] rounded-3xl border border-white/5 p-8">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-xl font-bold flex items-center space-x-2">
                                <BookOpen className="w-6 h-6 text-blue-400" />
                                <span>Academic Results</span>
                            </h3>
                        </div>

                        {results.length > 0 ? (
                            <div className="overflow-x-auto">
                                <table className="w-full text-left">
                                    <thead>
                                        <tr className="text-slate-500 text-xs font-bold uppercase tracking-wider border-b border-white/5">
                                            <th className="pb-4 pr-4">Subject</th>
                                            <th className="pb-4 px-4">Exam</th>
                                            <th className="pb-4 px-4">Test</th>
                                            <th className="pb-4 px-4">Total</th>
                                            <th className="pb-4 px-4">Grade</th>
                                            <th className="pb-4 pl-4 text-right">Term</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-white/5">
                                        {results.map((res: any) => {
                                            const { grade, remark, color } = getGrade(res.marks);
                                            // Split score: Exam = marks - testScore, Test = testScore
                                            const examScore = res.marks - (res.testScore || 0);
                                            
                                            return (
                                                <tr key={res.id} className="group hover:bg-white/5 transition-colors">
                                                    <td className="py-4 pr-4">
                                                        <span className="font-bold text-slate-200">{res.subject}</span>
                                                    </td>
                                                    <td className="py-4 px-4">
                                                        <span className="text-slate-400">{examScore.toFixed(1)}</span>
                                                    </td>
                                                    <td className="py-4 px-4 text-blue-400 font-bold">
                                                        {res.testScore || 0}
                                                    </td>
                                                    <td className="py-4 px-4">
                                                        <span className="text-white font-black text-lg">{res.marks}</span>
                                                    </td>
                                                    <td className="py-4 px-4">
                                                        <div className="flex flex-col">
                                                            <span className={`font-black ${color}`}>{grade}</span>
                                                            <span className="text-[10px] text-slate-500 uppercase font-bold">{remark}</span>
                                                        </div>
                                                    </td>
                                                    <td className="py-4 pl-4 text-right text-slate-500 text-sm whitespace-nowrap">
                                                        {res.term}
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                            <div className="text-center py-20">
                                <div className="w-16 h-16 bg-slate-800 rounded-2xl flex items-center justify-center mx-auto mb-4">
                                    <BookOpen className="w-8 h-8 text-slate-600" />
                                </div>
                                <p className="text-slate-500 font-medium mb-2">No results available yet</p>
                                <p className="text-slate-600 text-sm">Academic results will appear here once grades are posted</p>
                            </div>
                        )}
                    </div>

                    {/* Recent Activity */}
                    <div className="bg-[#11141b] rounded-3xl border border-white/5 p-8">
                        <h3 className="text-xl font-bold mb-6 flex items-center space-x-2">
                            <Bell className="w-6 h-6 text-indigo-400" />
                            <span>Recent Activity</span>
                        </h3>

                        <div className="space-y-6">
                            {results.slice(0, 5).map((res: any) => (
                                <div key={res.id} className="flex items-start space-x-4">
                                    <div className="w-8 h-8 bg-blue-600/10 rounded-lg flex items-center justify-center mt-1">
                                        <Award className="w-4 h-4 text-blue-400" />
                                    </div>
                                    <div>
                                        <p className="text-sm font-medium text-slate-300">New result posted for {res.subject}</p>
                                        <p className="text-xs text-slate-500">{new Date(res.createdAt).toLocaleDateString()}</p>
                                    </div>
                                </div>
                            ))}
                            {results.length === 0 && (
                                <div className="text-center py-12">
                                    <div className="w-12 h-12 bg-slate-800 rounded-xl flex items-center justify-center mx-auto mb-3">
                                        <Bell className="w-6 h-6 text-slate-600" />
                                    </div>
                                    <p className="text-slate-500 text-sm font-medium">No recent activity</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* Attendance Section */}
                <div className="mt-8 bg-[#11141b] rounded-3xl border border-white/5 p-8">
                    <h3 className="text-xl font-bold mb-6 flex items-center space-x-2">
                        <Calendar className="w-6 h-6 text-emerald-400" />
                        <span>Attendance Record</span>
                    </h3>

                    <div className="text-center py-12">
                        <div className="w-16 h-16 bg-slate-800 rounded-2xl flex items-center justify-center mx-auto mb-4">
                            <Calendar className="w-8 h-8 text-slate-600" />
                        </div>
                        <p className="text-slate-500 font-medium mb-2">No attendance records available</p>
                        <p className="text-slate-600 text-sm">Attendance data will be displayed here</p>
                    </div>
                </div>
            </main>
        </div>
    );
}
