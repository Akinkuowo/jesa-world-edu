"use client";

import { useEffect, useState } from "react";
import {
    GraduationCap,
    Book,
    Trophy,
    Calendar,
    MessageSquare,
    FileText,
    Clock,
    LogOut,
    ChevronRight,
    Star,
    CheckCircle,
    CalendarDays,
    ArrowLeft
} from "lucide-react";
import { useRouter } from "next/navigation";

export default function StudentDashboard() {
    const router = useRouter();
    const [user, setUser] = useState<any>(null);
    const [exams, setExams] = useState<any[]>([]);
    const [activeTab, setActiveTab] = useState<'dashboard' | 'exams'>('dashboard');

    useEffect(() => {
        const savedUser = localStorage.getItem("user");
        if (!savedUser) {
            router.push("/login");
        } else {
            setUser(JSON.parse(savedUser));
            fetchExams();
        }
    }, [router]);

    const fetchExams = async () => {
        try {
            const token = localStorage.getItem("token");
            if (!token) return;
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/student/exams`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) setExams(await res.json());
        } catch (err) {
            console.error("Failed to fetch exams", err);
        }
    };

    const handleLogout = () => {
        localStorage.clear();
        router.push("/login");
    };

    if (!user) return null;

    const today = new Date();
    // Use local time for YYYY-MM-DD formatting, not UTC (which is what toISOString does)
    const year = today.getFullYear();
    const month = String(today.getMonth() + 1).padStart(2, '0');
    const day = String(today.getDate()).padStart(2, '0');
    const todayString = `${year}-${month}-${day}`;
    
    const todaysExams = exams.filter(e => e.date === todayString);
    const upcomingExams = exams.filter(e => e.date > todayString);

    return (
        <div className="min-h-screen bg-[#f1f3f6] text-slate-900 font-sans pb-20">
            {/* Top Banner */}
            <div className="bg-indigo-700 h-64 w-full relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-r from-indigo-700 to-purple-700 opacity-90" />
                <div className="absolute -right-20 -top-20 w-80 h-80 bg-white/10 rounded-full blur-3xl" />
                <div className="absolute -left-20 -bottom-20 w-80 h-80 bg-white/10 rounded-full blur-3xl" />

                <div className="relative z-10 max-w-7xl mx-auto px-10 h-full flex flex-col justify-center">
                    <div className="flex items-center space-x-6">
                        <div className="w-24 h-24 bg-white rounded-3xl p-1 shadow-2xl">
                            <div className="w-full h-full bg-indigo-50 rounded-2xl flex items-center justify-center text-indigo-600 font-black text-3xl">
                                {user.firstName.charAt(0)}
                            </div>
                        </div>
                        <div className="text-white">
                            <h1 className="text-4xl font-black tracking-tight mb-2">Welcome, {user.firstName}!</h1>
                            <div className="flex items-center space-x-4 opacity-80 font-medium">
                                <span className="flex items-center gap-1.5"><GraduationCap className="w-4 h-4" /> Grade 11-B</span>
                                <span className="w-1.5 h-1.5 bg-white/40 rounded-full" />
                                <span className="flex items-center gap-1.5"><Star className="w-4 h-4" /> Top 5% of Class</span>
                            </div>
                        </div>
                        <button onClick={handleLogout} className="ml-auto p-4 bg-white/10 hover:bg-white/20 text-white rounded-2xl transition-all">
                            <LogOut className="w-6 h-6" />
                        </button>
                    </div>
                </div>
            </div>

            <div className="max-w-7xl mx-auto px-10 -mt-20 relative z-20">
                {activeTab === 'dashboard' ? (
                    <div className="grid lg:grid-cols-4 gap-8">
                        {/* Left Column - Quick Stats */}
                <div className="lg:col-span-1 space-y-6">
                    <div className="bg-white rounded-[2rem] p-8 shadow-xl shadow-slate-200/60 border border-white">
                        <h3 className="text-sm font-black text-slate-400 uppercase tracking-widest mb-6">Attendance</h3>
                        <div className="flex items-end justify-between">
                            <div className="text-5xl font-black text-slate-900">94<span className="text-2xl text-indigo-500">%</span></div>
                            <div className="text-emerald-500 text-xs font-bold mb-1 flex items-center gap-1">
                                <Star className="w-3 h-3 fill-emerald-500" /> Great!
                            </div>
                        </div>
                        <div className="mt-4 w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                            <div className="h-full bg-indigo-600 w-[94%]" />
                        </div>
                    </div>

                    <div className="bg-white rounded-[2rem] p-8 shadow-xl shadow-slate-200/60 border border-white">
                        <h3 className="text-sm font-black text-slate-400 uppercase tracking-widest mb-6">Your GPA</h3>
                        <div className="text-5xl font-black text-slate-900">3.82<span className="text-2xl text-slate-300">/4.0</span></div>
                        <p className="mt-2 text-xs font-bold text-slate-400">0.2 Improvement from last term</p>
                    </div>
                </div>

                {/* Center - Courses & Assignments */}
                <div className="lg:col-span-2 space-y-8">
                    <section className="bg-white rounded-[2.5rem] p-10 shadow-xl shadow-slate-200/60 border border-white">
                        <div className="flex items-center justify-between mb-8">
                            <h2 className="text-2xl font-black tracking-tight">Today's Exams</h2>
                            <button onClick={() => setActiveTab('exams')} className="text-indigo-600 text-sm font-bold flex items-center gap-1 hover:underline group">
                                See All <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                            </button>
                        </div>
                        {todaysExams.length > 0 ? (
                            <div className="grid md:grid-cols-2 gap-6">
                                {todaysExams.map(exam => (
                                    <ExamCard key={exam.id} exam={exam} color="indigo" onStart={() => router.push('/dashboard/student/exam/' + exam.id)} />
                                ))}
                            </div>
                        ) : (
                            <div className="py-10 text-center border-2 border-dashed border-slate-100 rounded-3xl">
                                <CheckCircle className="w-12 h-12 text-slate-200 mx-auto mb-4" />
                                <h3 className="text-slate-800 font-bold mb-1">No exams today!</h3>
                                <p className="text-xs text-slate-400 font-medium">You have a free schedule today.</p>
                            </div>
                        )}
                    </section>

                    <section className="bg-white rounded-[2.5rem] p-10 shadow-xl shadow-slate-200/60 border border-white">
                        <div className="flex items-center justify-between mb-8">
                            <h2 className="text-2xl font-black tracking-tight">Upcoming Exams</h2>
                            <CalendarDays className="w-6 h-6 text-slate-300" />
                        </div>
                        <div className="space-y-4">
                            {upcomingExams.length > 0 ? (
                                upcomingExams.slice(0, 5).map(exam => (
                                    <UpcomingExamItem key={exam.id} exam={exam} />
                                ))
                            ) : (
                                <p className="text-sm font-medium text-slate-400 text-center py-6">No upcoming exams scheduled.</p>
                            )}
                        </div>
                    </section>
                </div>

                {/* Right Column - Side Features */}
                <div className="lg:col-span-1 space-y-6">
                    <div className="grid grid-cols-2 gap-4">
                        <QuickMenu icon={<MessageSquare />} label="Chat" />
                        <QuickMenu icon={<FileText />} label="Reports" />
                        <QuickMenu icon={<Calendar />} label="Events" />
                        <QuickMenu icon={<Trophy />} label="Awards" />
                    </div>

                    <div className="bg-slate-900 rounded-[2rem] p-8 text-white shadow-2xl overflow-hidden relative group">
                        <div className="absolute -right-10 -bottom-10 w-40 h-40 bg-indigo-500/20 rounded-full blur-2xl group-hover:scale-150 transition-transform duration-700" />
                        <h4 className="text-xl font-black mb-4 relative z-10">Library Access</h4>
                        <p className="text-xs text-slate-400 mb-6 relative z-10 leading-relaxed">You have 2 items overdue and 1 item currently borrowed from the digital library.</p>
                        <button className="w-full bg-white text-slate-900 py-3 rounded-2xl font-bold text-sm relative z-10 hover:bg-slate-100 transition-colors">Manage Books</button>
                    </div>
                </div>
                    </div>
                ) : (
                    <StudentExamsView exams={exams} onBack={() => setActiveTab('dashboard')} onStart={(id) => router.push('/dashboard/student/exam/' + id)} />
                )}
            </div>
        </div>
    );
}

function ExamCard({ exam, color, onStart }: { exam: any, color: string, onStart?: () => void }) {
    const colors: any = {
        indigo: "bg-indigo-500",
        purple: "bg-purple-500",
        orange: "bg-orange-500",
        emerald: "bg-emerald-500"
    };

    return (
        <div className="p-6 rounded-3xl bg-slate-50 border border-slate-100 hover:border-indigo-200 transition-all cursor-pointer group hover:bg-white hover:shadow-xl hover:shadow-indigo-500/5">
            <div className="w-10 h-10 rounded-xl bg-white shadow-sm flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <Book className={`w-5 h-5 text-indigo-500`} />
            </div>
            <h4 className="font-bold text-slate-900 mb-1">{exam.subject}</h4>
            <div className="flex items-center gap-2 mb-6">
                <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{exam.type}</p>
                <div className="w-1 h-1 bg-slate-300 rounded-full" />
                <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{exam.duration} MINS</p>
            </div>
            <div className="flex items-center justify-between pt-4 border-t border-slate-100">
                <div className="flex flex-col">
                    <span className="text-[10px] text-slate-400 font-bold mb-0.5">TIME</span>
                    <span className="text-xs font-black text-slate-700">{exam.time}</span>
                </div>
                {exam.hasSubmitted ? (
                    <button disabled className="px-4 py-2 bg-emerald-50 text-emerald-600 font-bold text-xs rounded-xl cursor-not-allowed">
                        Completed
                    </button>
                ) : (
                    <button 
                        onClick={onStart}
                        className="px-4 py-2 bg-indigo-50 text-indigo-600 font-bold text-xs rounded-xl group-hover:bg-indigo-600 group-hover:text-white transition-colors"
                    >
                        Start Exam
                    </button>
                )}
            </div>
        </div>
    );
}

function UpcomingExamItem({ exam }: { exam: any }) {
    // Format date nicely (e.g., "Tomorrow", "Friday", "Oct 12")
    const examDate = new Date(exam.date + 'T00:00:00'); // Force local timezone
    const today = new Date();
    today.setHours(0,0,0,0);
    const diffTime = Math.abs(examDate.getTime() - today.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    let dateStr = exam.date;
    let urgencyClass = "bg-slate-200";

    if (diffDays === 1) {
        dateStr = `Tomorrow, ${exam.time}`;
        urgencyClass = "bg-red-500";
    } else if (diffDays <= 7) {
        dateStr = `${examDate.toLocaleDateString('en-US', { weekday: 'long' })}, ${exam.time}`;
        urgencyClass = "bg-amber-500";
    } else {
        dateStr = `${examDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}, ${exam.time}`;
        urgencyClass = "bg-emerald-500";
    }

    return (
        <div className="flex items-center p-4 bg-slate-50 rounded-2xl border border-slate-100 hover:shadow-md transition-shadow cursor-pointer group hover:bg-white">
            <div className={`w-1.5 h-8 rounded-full ${urgencyClass} mr-4 transition-colors`} />
            <div className="flex-1">
                <div className="flex items-center gap-2 mb-0.5">
                    <h5 className="font-bold text-sm text-slate-800">{exam.subject}</h5>
                    <span className="px-2 py-0.5 bg-slate-100 text-slate-500 rounded-full text-[9px] font-black tracking-widest uppercase">{exam.type}</span>
                </div>
                <p className="text-[10px] font-bold text-slate-400 uppercase flex items-center gap-1">
                    <Clock className="w-3 h-3" /> {exam.duration} Minutes
                </p>
            </div>
            <div className="text-right">
                <div className="text-xs font-black text-slate-900">{dateStr}</div>
                <div className="text-[10px] text-slate-400 font-bold mt-0.5">{new Date(exam.date + 'T00:00:00').toLocaleDateString()}</div>
            </div>
        </div>
    );
}

function QuickMenu({ icon, label }: { icon: any, label: string }) {
    return (
        <div className="flex flex-col items-center justify-center p-6 bg-white rounded-3xl border border-white shadow-lg shadow-slate-200/40 hover:scale-105 transition-all text-slate-400 hover:text-indigo-600 hover:shadow-indigo-500/10">
            <div className="mb-2">{icon}</div>
            <span className="text-[10px] font-black uppercase tracking-widest">{label}</span>
        </div>
    );
}

function StudentExamsView({ exams, onBack, onStart }: { exams: any[], onBack: () => void, onStart: (id: string) => void }) {
    return (
        <div className="bg-white rounded-[2.5rem] p-10 shadow-xl shadow-slate-200/60 border border-white min-h-[60vh]">
            <div className="flex items-center justify-between mb-10 border-b border-slate-100 pb-6">
                <div className="flex items-center gap-4">
                    <button onClick={onBack} className="p-3 bg-slate-50 hover:bg-slate-100 rounded-2xl transition-colors text-slate-600">
                        <ArrowLeft className="w-5 h-5" />
                    </button>
                    <div>
                        <h2 className="text-3xl font-black tracking-tight text-slate-900">All Scheduled Exams</h2>
                        <p className="text-slate-500 font-medium text-sm mt-1">View your complete examination schedule</p>
                    </div>
                </div>
            </div>

            {exams.length > 0 ? (
                <div className="space-y-4">
                    {exams.map(exam => {
                        const examDate = new Date(exam.date + 'T00:00:00'); // Force local midnight parsing
                        const today = new Date();
                        today.setHours(0,0,0,0);
                        const isPast = examDate < today;
                        const isToday = examDate.getTime() === today.getTime();
                        const isCompleted = exam.hasSubmitted;
                        const isDisabled = isPast || isCompleted;

                        return (
                            <div key={exam.id} className={`flex items-center p-6 rounded-3xl border transition-all hover:shadow-lg ${
                                isCompleted ? 'bg-emerald-50/50 border-emerald-100' :
                                isPast ? 'bg-slate-50 border-slate-100' : 
                                isToday ? 'bg-indigo-50/50 border-indigo-100 shadow-indigo-500/5' : 
                                'bg-white border-slate-100 hover:border-indigo-200'
                            }`}>
                                <div className={`w-16 h-16 rounded-2xl flex flex-col items-center justify-center flex-shrink-0 mr-6 ${
                                    isCompleted ? 'bg-emerald-100 text-emerald-600' :
                                    isPast ? 'bg-slate-200 text-slate-500' :
                                    isToday ? 'bg-indigo-500 text-white shadow-lg shadow-indigo-500/30' :
                                    'bg-indigo-50 text-indigo-600'
                                }`}>
                                    <span className="text-xs font-bold uppercase tracking-widest opacity-80">{examDate.toLocaleDateString('en-US', { month: 'short' })}</span>
                                    <span className="text-xl font-black">{examDate.getDate()}</span>
                                </div>
                                <div className="flex-1">
                                    <div className="flex items-center gap-3 mb-1">
                                        <h3 className="text-lg font-black text-slate-800">{exam.subject}</h3>
                                        {isCompleted && <span className="px-2.5 py-0.5 bg-emerald-100 text-emerald-700 rounded-full text-[10px] font-black tracking-widest uppercase">Done</span>}
                                        {isToday && !isCompleted && <span className="px-2.5 py-0.5 bg-indigo-100 text-indigo-700 rounded-full text-[10px] font-black tracking-widest uppercase">Today</span>}
                                        {isPast && !isCompleted && <span className="px-2.5 py-0.5 bg-slate-200 text-slate-600 rounded-full text-[10px] font-black tracking-widest uppercase">Past</span>}
                                    </div>
                                    <div className="flex items-center gap-4">
                                        <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">{exam.type}</p>
                                        <div className="w-1 h-1 bg-slate-300 rounded-full" />
                                        <p className="text-xs font-bold text-slate-500 flex items-center gap-1.5">
                                            <Clock className="w-3.5 h-3.5" /> {exam.time}
                                        </p>
                                        <div className="w-1 h-1 bg-slate-300 rounded-full" />
                                        <p className="text-xs font-bold text-slate-500">{exam.duration} mins</p>
                                    </div>
                                </div>
                                <div>
                                    <button 
                                        onClick={() => (!isDisabled && onStart) ? onStart(exam.id) : null}
                                        className={`px-6 py-3 rounded-2xl font-bold text-sm transition-colors ${
                                        isCompleted ? 'bg-emerald-100 text-emerald-700 cursor-not-allowed' :
                                        isPast ? 'bg-slate-100 text-slate-400 cursor-not-allowed' :
                                        isToday ? 'bg-indigo-600 hover:bg-indigo-700 text-white shadow-lg shadow-indigo-500/20' :
                                        'bg-indigo-50 hover:bg-indigo-100 text-indigo-600'
                                    }`} disabled={isDisabled}>
                                        {isCompleted ? 'Completed' : isPast ? 'Missed' : 'Start Exam'}
                                    </button>
                                </div>
                            </div>
                        );
                    })}
                </div>
            ) : (
                <div className="py-20 text-center border-2 border-dashed border-slate-100 rounded-[2rem]">
                    <CalendarDays className="w-16 h-16 text-slate-200 mx-auto mb-6" />
                    <h3 className="text-xl font-black text-slate-800 mb-2">No Exams Found</h3>
                    <p className="text-slate-500 font-medium">There are currently no exams scheduled for your enrolled subjects.</p>
                </div>
            )}
        </div>
    );
}
