"use client";

import { useEffect, useState } from "react";
import {
    BookOpen,
    Users,
    Award,
    Calendar,
    Clock,
    Notebook,
    LogOut,
    LayoutDashboard,
    CheckCircle2,
    AlertCircle,
    FileText,
    Brain,
    Menu,
    X
} from "lucide-react";
import { useRouter } from "next/navigation";
import StudentsView from "./components/Students";
import LessonNotebook from "./components/LessonNotebook";
import Assignments from "./components/Assignments";
import ExamSetter from "./components/ExamSetter";
import StudentAwards from "./components/StudentAwards";
import ClassCalendar from "./components/ClassCalendar";
import { Loader2 } from "lucide-react";

export default function TeacherDashboard() {
    const router = useRouter();
    const [user, setUser] = useState<any>(null);
    const [activeView, setActiveView] = useState<'DASHBOARD' | 'STUDENTS' | 'NOTEBOOK' | 'ASSIGNMENTS' | 'EXAMS' | 'AWARDS' | 'CALENDAR'>('DASHBOARD');
    const [stats, setStats] = useState({
        studentCount: 0,
        lessonNotesCount: 0,
        assignmentsCount: 0,
        classesTodayCount: 0
    });
    const [loadingStats, setLoadingStats] = useState(true);
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);

    const fetchStats = async () => {
        setLoadingStats(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/dashboard-stats`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = await res.json();
            if (res.ok) {
                setStats({
                    studentCount: data.studentCount || 0,
                    lessonNotesCount: data.lessonNotesCount || 0,
                    assignmentsCount: data.assignmentsCount || 0,
                    classesTodayCount: data.classesTodayCount || 0
                });
            }
        } catch (err) {
            console.error("Failed to fetch dashboard stats:", err);
        } finally {
            setLoadingStats(false);
        }
    };

    useEffect(() => {
        const savedUser = localStorage.getItem("user");
        if (!savedUser) {
            router.push("/login");
        } else {
            setUser(JSON.parse(savedUser));
            fetchStats();
        }
    }, [router]);

    const handleLogout = () => {
        localStorage.clear();
        router.push("/login");
    };

    if (!user) return null;

    return (
        <div className="min-h-screen bg-[#fafafa] text-slate-900">
            {/* Mobile Overlay */}
            {isSidebarOpen && (
                <div 
                    className="fixed inset-0 bg-black/50 z-30 lg:hidden backdrop-blur-sm transition-opacity"
                    onClick={() => setIsSidebarOpen(false)}
                />
            )}

            {/* Sidebar */}
            <aside className={`fixed left-0 top-0 h-full w-24 bg-white border-r border-slate-200 z-40 flex flex-col items-center py-8 space-y-8 shadow-sm transition-transform duration-300 lg:translate-x-0 ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
                <div className="w-12 h-12 bg-emerald-600 rounded-2xl flex items-center justify-center text-white shadow-lg shadow-emerald-500/20">
                    <BookOpen className="w-6 h-6" />
                </div>
                <nav className="flex-1 flex flex-col space-y-4">
                    <SideIcon icon={<LayoutDashboard />} active={activeView === 'DASHBOARD'} onClick={() => { setActiveView('DASHBOARD'); setIsSidebarOpen(false); }} />
                    <SideIcon icon={<Users />} active={activeView === 'STUDENTS'} onClick={() => { setActiveView('STUDENTS'); setIsSidebarOpen(false); }} />
                    <SideIcon icon={<Notebook />} active={activeView === 'NOTEBOOK'} onClick={() => { setActiveView('NOTEBOOK'); setIsSidebarOpen(false); }} />
                    <SideIcon icon={<FileText />} active={activeView === 'ASSIGNMENTS'} onClick={() => { setActiveView('ASSIGNMENTS'); setIsSidebarOpen(false); }} />
                    <SideIcon icon={<Brain />} active={activeView === 'EXAMS'} onClick={() => { setActiveView('EXAMS'); setIsSidebarOpen(false); }} />
                    <SideIcon icon={<Award />} active={activeView === 'AWARDS'} onClick={() => { setActiveView('AWARDS'); setIsSidebarOpen(false); }} />
                    <SideIcon icon={<Calendar />} active={activeView === 'CALENDAR'} onClick={() => { setActiveView('CALENDAR'); setIsSidebarOpen(false); }} />
                </nav>
                <button onClick={handleLogout} className="p-3 text-slate-400 hover:text-red-500 hover:bg-red-50 rounded-xl transition-all">
                    <LogOut className="w-6 h-6" />
                </button>
            </aside>

            <main className="lg:pl-24 transition-all">
                {/* Header */}
                <div className="bg-white border-b border-slate-200 px-6 lg:px-10 py-6 flex items-center justify-between sticky top-0 z-10">
                    <div className="flex items-center gap-4">
                        <button 
                            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
                            className="lg:hidden p-2 hover:bg-slate-100 rounded-xl transition-colors text-slate-600"
                        >
                            {isSidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
                        </button>
                        <h1 className="text-lg lg:text-xl font-bold text-slate-800 truncate max-w-[200px] md:max-w-none">
                            {activeView === 'DASHBOARD' ? `Hi, Prof. ${user.lastName}! 👋` :
                                activeView === 'STUDENTS' ? 'My Students' :
                                    activeView === 'NOTEBOOK' ? 'Lesson Notebook' :
                                        activeView === 'ASSIGNMENTS' ? 'Assignments' :
                                            activeView === 'EXAMS' ? 'Set Exams' :
                                                activeView === 'AWARDS' ? 'Student Awards' :
                                                    'Class Calendar'}
                        </h1>
                    </div>
                    <div className="flex items-center space-x-3 lg:space-x-6">
                        <div className="hidden md:flex items-center space-x-2 text-slate-500">
                            <Calendar className="w-4 h-4" />
                            <span className="text-sm font-medium">Monday, 24th May</span>
                        </div>
                        <div className="flex items-center space-x-3 pl-3 lg:pl-6 border-l border-slate-200">
                            <div className="text-right hidden sm:block">
                                <div className="text-sm font-bold">{user.firstName} {user.lastName}</div>
                                <div className="text-[10px] font-bold text-emerald-600 uppercase tracking-widest leading-none mt-1">Senior Lecturer</div>
                            </div>
                            <div className="w-10 h-10 bg-slate-100 rounded-full border-2 border-white shadow-sm flex items-center justify-center text-slate-600 font-bold">
                                {user.firstName.charAt(0)}
                            </div>
                        </div>
                    </div>
                </div>

                <div className="p-6 lg:p-10 max-w-7xl mx-auto">
                    {activeView === 'DASHBOARD' ? (
                        /* Dashboard Grid */
                        <div className="grid lg:grid-cols-3 gap-8">

                            {/* Left Col: Main Stats & Schedule */}
                            <div className="lg:col-span-2 space-y-8">
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                    <MiniStat value={loadingStats ? "..." : stats.studentCount.toString()} label="Students" icon={<Users />} bg="bg-blue-500" />
                                    <MiniStat value={loadingStats ? "..." : stats.lessonNotesCount.toString()} label="Lesson Notes" icon={<Notebook />} bg="bg-indigo-500" />
                                    <MiniStat value={loadingStats ? "..." : stats.assignmentsCount.toString()} label="Assignments" icon={<FileText />} bg="bg-purple-500" />
                                </div>

                                <section className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm">
                                    <div className="flex items-center justify-between mb-8">
                                        <h2 className="text-lg font-bold flex items-center space-x-2">
                                            <span>Current Class Schedule</span>
                                            <span className="px-2 py-0.5 bg-emerald-100 text-emerald-700 text-[10px] rounded-full uppercase font-black">Today</span>
                                        </h2>
                                        <button className="text-emerald-600 text-xs font-bold hover:underline">View Weekly</button>
                                    </div>
                                    <div className="space-y-4">
                                        <ScheduleItem time="09:00 AM" subject="Advanced Mathematics" room="Room 204" active />
                                        <ScheduleItem time="11:30 AM" subject="Physics Lab" room="Science Wing" />
                                        <ScheduleItem time="02:00 PM" subject="Quantum Mechanics" room="Hall A" />
                                    </div>
                                </section>
                            </div>

                            {/* Right Col: Announcements & Quick Info */}
                            <div className="space-y-8">
                                <section className="bg-indigo-900 text-white rounded-3xl p-8 shadow-xl shadow-indigo-900/10">
                                    <h3 className="text-lg font-bold mb-4">Exam Reminder</h3>
                                    <p className="text-sm text-indigo-100/70 mb-6">Mid-term grading period ends in 3 days. Please ensure all student marks are uploaded.</p>
                                    <button className="w-full bg-indigo-500 hover:bg-indigo-400 py-3 rounded-xl font-bold transition-all flex items-center justify-center space-x-2 group">
                                        <span>Open Gradebook</span>
                                        <CheckCircle2 className="w-4 h-4 group-hover:scale-110 transition-transform" />
                                    </button>
                                </section>

                                <section className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm">
                                    <h3 className="text-lg font-bold mb-6">Notifications</h3>
                                    <div className="space-y-6">
                                        <NotifyItem
                                            icon={<AlertCircle className="text-amber-500" />}
                                            msg="3 Students missed Mathematics submission"
                                            time="2 hrs ago"
                                        />
                                        <NotifyItem
                                            icon={<Users className="text-blue-500" />}
                                            msg="Parent-Teacher meeting scheduled for Friday"
                                            time="5 hrs ago"
                                        />
                                        <NotifyItem
                                            icon={<CheckCircle2 className="text-emerald-500" />}
                                            msg="Physics lab material approved by Admin"
                                            time="Yesterday"
                                        />
                                    </div>
                                </section>
                            </div>
                        </div>
                    ) : activeView === 'STUDENTS' ? (
                        <StudentsView />
                    ) : activeView === 'NOTEBOOK' ? (
                        <LessonNotebook />
                    ) : activeView === 'ASSIGNMENTS' ? (
                        <Assignments />
                    ) : activeView === 'EXAMS' ? (
                        <ExamSetter />
                    ) : activeView === 'AWARDS' ? (
                        <StudentAwards />
                    ) : activeView === 'CALENDAR' ? (
                        <ClassCalendar />
                    ) : (
                        <div className="bg-white rounded-[2rem] border border-slate-200 p-20 text-center shadow-sm">
                            <h2 className="text-2xl font-black text-slate-900 mb-2">Coming Soon</h2>
                            <p className="text-slate-500 font-medium">This feature is currently under development.</p>
                        </div>
                    )}
                </div>
            </main>
        </div>
    );
}

function SideIcon({ icon, active = false, onClick }: { icon: any, active?: boolean, onClick?: () => void }) {
    return (
        <button
            onClick={onClick}
            className={`p-4 rounded-2xl transition-all group ${active ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-600/20' : 'text-slate-400 hover:bg-slate-50 hover:text-slate-600'
                }`}>
            {icon}
        </button>
    );
}

function MiniStat({ value, label, icon, bg }: { value: string, label: string, icon: any, bg: string }) {
    return (
        <div className="bg-white p-6 rounded-3xl border border-slate-200 flex items-center space-x-5 shadow-sm hover:shadow-md transition-shadow">
            <div className={`w-12 h-12 rounded-2xl ${bg} flex items-center justify-center text-white shadow-lg`}>
                {icon}
            </div>
            <div>
                <div className="text-2xl font-black text-slate-900">{value}</div>
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{label}</div>
            </div>
        </div>
    );
}

function ScheduleItem({ time, subject, room, active = false }: { time: string, subject: string, room: string, active?: boolean }) {
    return (
        <div className={`flex items-center p-5 rounded-2xl border transition-all ${active ? 'bg-emerald-50 border-emerald-100 scale-[1.02] shadow-sm' : 'bg-slate-50 border-slate-100 grayscale-[0.5] opacity-60'
            }`}>
            <div className="w-24 text-sm font-bold text-slate-400">{time}</div>
            <div className="flex-1">
                <div className={`font-bold ${active ? 'text-emerald-900' : 'text-slate-600'}`}>{subject}</div>
                <div className="text-xs font-semibold text-slate-400">{room}</div>
            </div>
            {active && (
                <div className="flex items-center space-x-2 text-[10px] font-bold text-emerald-600 uppercase bg-white px-3 py-1 rounded-full shadow-sm">
                    <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    <span>In Progress</span>
                </div>
            )}
        </div>
    );
}

function NotifyItem({ icon, msg, time }: { icon: any, msg: string, time: string }) {
    return (
        <div className="flex gap-4">
            <div className="mt-1">{icon}</div>
            <div>
                <p className="text-sm font-semibold text-slate-700 leading-snug">{msg}</p>
                <span className="text-[10px] font-bold text-slate-400 uppercase">{time}</span>
            </div>
        </div>
    );
}
