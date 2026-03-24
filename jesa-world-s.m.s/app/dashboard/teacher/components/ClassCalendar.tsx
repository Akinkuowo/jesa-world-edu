"use client";

import { useState, useEffect, useMemo } from "react";
import {
    ChevronLeft,
    ChevronRight,
    CalendarDays,
    Clock,
    BookOpen,
    Users,
    GraduationCap,
    Info,
    X
} from "lucide-react";

interface ExamSchedule {
    id: string;
    subject: string;
    class: string;
    date: string; // e.g. "2026-03-20"
    time: string; // e.g. "09:00 AM"
    duration: string; // e.g. "2 hours"
    type: string; // e.g. "First Term"
}

const TYPE_COLORS: Record<string, { bg: string; text: string; dot: string; border: string }> = {
    "First Term":  { bg: "bg-indigo-50",  text: "text-indigo-700",  dot: "bg-indigo-500",  border: "border-l-indigo-500" },
    "Second Term": { bg: "bg-emerald-50", text: "text-emerald-700", dot: "bg-emerald-500", border: "border-l-emerald-500" },
    "Third Term":  { bg: "bg-amber-50",   text: "text-amber-700",   dot: "bg-amber-500",   border: "border-l-amber-500" },
    "MOCK":        { bg: "bg-purple-50",  text: "text-purple-700",  dot: "bg-purple-500",  border: "border-l-purple-500" },
    "WAEC":        { bg: "bg-rose-50",    text: "text-rose-700",    dot: "bg-rose-500",    border: "border-l-rose-500" },
    "default":     { bg: "bg-slate-50",   text: "text-slate-700",   dot: "bg-slate-400",   border: "border-l-slate-400" },
};

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
];

function typeColor(type: string) {
    return TYPE_COLORS[type] ?? TYPE_COLORS["default"];
}

function parseDate(dateStr: string): Date | null {
    if (!dateStr) return null;
    const d = new Date(dateStr);
    return isNaN(d.getTime()) ? null : d;
}

function isSameDay(a: Date, b: Date) {
    return a.getFullYear() === b.getFullYear() &&
        a.getMonth() === b.getMonth() &&
        a.getDate() === b.getDate();
}

export default function ClassCalendar() {
    const [exams, setExams] = useState<ExamSchedule[]>([]);
    const [loading, setLoading] = useState(true);
    const today = new Date();
    const [currentYear, setCurrentYear] = useState(today.getFullYear());
    const [currentMonth, setCurrentMonth] = useState(today.getMonth());
    const [selectedDay, setSelectedDay] = useState<Date | null>(null);
    const [detailEvent, setDetailEvent] = useState<ExamSchedule | null>(null);

    useEffect(() => {
        const fetchExams = async () => {
            setLoading(true);
            try {
                const token = localStorage.getItem("token");
                const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/teacher/exams`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                if (res.ok) {
                    const data = await res.json();
                    setExams(data);
                }
            } catch (err) {
                console.error("Failed to fetch exams:", err);
            } finally {
                setLoading(false);
            }
        };
        fetchExams();
    }, []);

    // Grid of days for the current month view
    const calendarDays = useMemo(() => {
        const firstDay = new Date(currentYear, currentMonth, 1).getDay();
        const daysInMonth = new Date(currentYear, currentMonth + 1, 0).getDate();
        const days: (Date | null)[] = [];
        for (let i = 0; i < firstDay; i++) days.push(null);
        for (let d = 1; d <= daysInMonth; d++) {
            days.push(new Date(currentYear, currentMonth, d));
        }
        // pad to full weeks
        while (days.length % 7 !== 0) days.push(null);
        return days;
    }, [currentYear, currentMonth]);

    // Map of date-string -> exams
    const examsByDate = useMemo(() => {
        const map: Record<string, ExamSchedule[]> = {};
        exams.forEach(e => {
            const d = parseDate(e.date);
            if (!d) return;
            const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
            if (!map[key]) map[key] = [];
            map[key].push(e);
        });
        return map;
    }, [exams]);

    const getExamsForDay = (day: Date) => {
        const key = `${day.getFullYear()}-${day.getMonth()}-${day.getDate()}`;
        return examsByDate[key] || [];
    };

    const selectedDayExams = selectedDay ? getExamsForDay(selectedDay) : [];

    const prevMonth = () => {
        if (currentMonth === 0) { setCurrentMonth(11); setCurrentYear(y => y - 1); }
        else setCurrentMonth(m => m - 1);
        setSelectedDay(null);
    };
    const nextMonth = () => {
        if (currentMonth === 11) { setCurrentMonth(0); setCurrentYear(y => y + 1); }
        else setCurrentMonth(m => m + 1);
        setSelectedDay(null);
    };

    // Upcoming events list (next 30 days from today)
    const upcomingExams = useMemo(() => {
        const in30 = new Date(today);
        in30.setDate(in30.getDate() + 30);
        return exams
            .map(e => ({ ...e, _date: parseDate(e.date) }))
            .filter(e => e._date && e._date >= today && e._date <= in30)
            .sort((a, b) => (a._date!.getTime() - b._date!.getTime()));
    }, [exams, today]);

    return (
        <div className="flex flex-col gap-8 relative">
            {/* Header */}
            <div>
                <h2 className="text-3xl font-black text-slate-800 tracking-tight">Class Calendar</h2>
                <p className="text-slate-500 text-sm font-medium mt-1">Exam and class schedules for your subjects</p>
            </div>

            <div className="flex flex-col xl:flex-row gap-8">
                {/* Calendar Grid */}
                <div className="flex-1 bg-white rounded-[2.5rem] border border-slate-100 shadow-xl shadow-slate-100/50 overflow-hidden">
                    {/* Month Navigation */}
                    <div className="flex items-center justify-between px-8 py-6 border-b border-slate-100">
                        <button
                            onClick={prevMonth}
                            className="p-2.5 rounded-xl hover:bg-slate-100 text-slate-500 hover:text-slate-800 transition-all"
                        >
                            <ChevronLeft className="w-5 h-5" />
                        </button>
                        <div className="text-center">
                            <h3 className="text-xl font-black text-slate-800 tracking-tight">
                                {MONTHS[currentMonth]} {currentYear}
                            </h3>
                        </div>
                        <button
                            onClick={nextMonth}
                            className="p-2.5 rounded-xl hover:bg-slate-100 text-slate-500 hover:text-slate-800 transition-all"
                        >
                            <ChevronRight className="w-5 h-5" />
                        </button>
                    </div>

                    {/* Day Headers */}
                    <div className="grid grid-cols-7 border-b border-slate-50">
                        {DAYS.map(d => (
                            <div key={d} className="py-3 text-center text-[10px] font-black text-slate-400 uppercase tracking-[0.15em]">
                                {d}
                            </div>
                        ))}
                    </div>

                    {/* Calendar Days */}
                    {loading ? (
                        <div className="flex items-center justify-center h-64">
                            <div className="w-8 h-8 rounded-full border-4 border-indigo-500 border-t-transparent animate-spin" />
                        </div>
                    ) : (
                        <div className="grid grid-cols-7">
                            {calendarDays.map((day, i) => {
                                if (!day) return <div key={`empty-${i}`} className="min-h-[80px] border-b border-r border-slate-50 bg-slate-50/30" />;

                                const isToday = isSameDay(day, today);
                                const isSelected = selectedDay && isSameDay(day, selectedDay);
                                const dayExams = getExamsForDay(day);
                                const isPast = day < today && !isToday;

                                return (
                                    <button
                                        key={day.toISOString()}
                                        onClick={() => setSelectedDay(isSelected ? null : day)}
                                        className={`min-h-[80px] p-2 border-b border-r border-slate-50 text-left transition-all group flex flex-col ${
                                            isSelected ? 'bg-indigo-50 ring-2 ring-inset ring-indigo-500/20' :
                                            isToday ? 'bg-emerald-50/60' :
                                            isPast ? 'bg-slate-50/50' :
                                            'hover:bg-slate-50'
                                        }`}
                                    >
                                        <span className={`w-7 h-7 flex items-center justify-center text-sm font-black rounded-full transition-all mb-1 ${
                                            isToday ? 'bg-emerald-500 text-white shadow-lg shadow-emerald-500/30' :
                                            isSelected ? 'bg-indigo-600 text-white' :
                                            isPast ? 'text-slate-300' :
                                            'text-slate-700 group-hover:bg-slate-200'
                                        }`}>
                                            {day.getDate()}
                                        </span>
                                        <div className="flex flex-col gap-0.5 w-full">
                                            {dayExams.slice(0, 2).map(exam => {
                                                const c = typeColor(exam.type);
                                                return (
                                                    <div key={exam.id} className={`text-[9px] font-black px-1.5 py-0.5 rounded-md truncate ${c.bg} ${c.text}`}>
                                                        {exam.subject}
                                                    </div>
                                                );
                                            })}
                                            {dayExams.length > 2 && (
                                                <div className="text-[9px] font-black text-slate-400 px-1.5">+{dayExams.length - 2} more</div>
                                            )}
                                        </div>
                                    </button>
                                );
                            })}
                        </div>
                    )}

                    {/* Selected Day Panel */}
                    {selectedDay && (
                        <div className="border-t border-slate-100 p-6 bg-slate-50/60">
                            <h4 className="text-sm font-black text-slate-800 mb-4">
                                {selectedDay.toLocaleDateString("en-GB", { weekday: 'long', day: 'numeric', month: 'long' })}
                            </h4>
                            {selectedDayExams.length === 0 ? (
                                <p className="text-sm text-slate-400 font-bold text-center py-4">No exams scheduled for this day.</p>
                            ) : (
                                <div className="space-y-3">
                                    {selectedDayExams.map(exam => {
                                        const c = typeColor(exam.type);
                                        return (
                                            <div
                                                key={exam.id}
                                                onClick={() => setDetailEvent(exam)}
                                                className={`flex items-center gap-4 p-4 rounded-2xl bg-white border-l-4 ${c.border} shadow-sm cursor-pointer hover:shadow-md transition-all`}
                                            >
                                                <div className={`w-2.5 h-2.5 rounded-full ${c.dot} flex-shrink-0`} />
                                                <div className="flex-1 min-w-0">
                                                    <p className="font-black text-slate-800 text-sm truncate">{exam.subject}</p>
                                                    <p className="text-xs font-bold text-slate-500 mt-0.5">Class {exam.class} · {exam.time} · {exam.duration}</p>
                                                </div>
                                                <span className={`text-[9px] font-black px-2 py-1 rounded-lg uppercase tracking-wider ${c.bg} ${c.text}`}>{exam.type}</span>
                                                <Info className="w-4 h-4 text-slate-300 flex-shrink-0" />
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {/* Right Sidebar */}
                <div className="xl:w-80 flex flex-col gap-6">
                    {/* Legend */}
                    <div className="bg-white rounded-[2rem] border border-slate-100 p-6 shadow-sm">
                        <h4 className="text-xs font-black text-slate-400 uppercase tracking-[0.15em] mb-4">Exam Types</h4>
                        <div className="space-y-3">
                            {Object.entries(TYPE_COLORS).filter(([k]) => k !== 'default').map(([label, c]) => (
                                <div key={label} className="flex items-center gap-3">
                                    <div className={`w-3 h-3 rounded-full ${c.dot} flex-shrink-0`} />
                                    <span className="text-sm font-bold text-slate-700">{label}</span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Today's highlight */}
                    <div className="bg-white rounded-[2rem] border border-slate-100 p-6 shadow-sm">
                        <div className="flex items-center space-x-3 mb-4">
                            <div className="w-8 h-8 bg-emerald-500 rounded-xl flex items-center justify-center">
                                <CalendarDays className="w-4 h-4 text-white" />
                            </div>
                            <h4 className="text-sm font-black text-slate-800">Today's Exams</h4>
                        </div>
                        {getExamsForDay(today).length === 0 ? (
                            <p className="text-xs font-bold text-slate-400 text-center py-3">No exams today</p>
                        ) : (
                            <div className="space-y-2">
                                {getExamsForDay(today).map(exam => {
                                    const c = typeColor(exam.type);
                                    return (
                                        <div key={exam.id} className={`p-3 rounded-xl ${c.bg}`}>
                                            <p className={`font-black text-sm ${c.text}`}>{exam.subject}</p>
                                            <p className="text-[10px] font-bold text-slate-500 mt-0.5 flex items-center gap-1">
                                                <Clock className="w-3 h-3" /> {exam.time} — {exam.duration}
                                            </p>
                                            <p className="text-[10px] font-bold text-slate-500 flex items-center gap-1 mt-0.5">
                                                <Users className="w-3 h-3" /> Class {exam.class}
                                            </p>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>

                    {/* Upcoming Events */}
                    <div className="bg-white rounded-[2rem] border border-slate-100 p-6 shadow-sm flex-1">
                        <h4 className="text-xs font-black text-slate-400 uppercase tracking-[0.15em] mb-4">Upcoming (30 days)</h4>
                        {upcomingExams.length === 0 ? (
                            <p className="text-xs font-bold text-slate-400 text-center py-6">No upcoming exams in the next 30 days</p>
                        ) : (
                            <div className="space-y-3 overflow-y-auto max-h-80">
                                {upcomingExams.map(exam => {
                                    const c = typeColor(exam.type);
                                    const d = exam._date!;
                                    return (
                                        <div
                                            key={exam.id}
                                            onClick={() => setDetailEvent(exam)}
                                            className="flex items-start gap-3 cursor-pointer group"
                                        >
                                            <div className="flex flex-col items-center w-9 flex-shrink-0 text-center">
                                                <span className="text-[9px] font-black text-slate-400 uppercase">{MONTHS[d.getMonth()].slice(0,3)}</span>
                                                <span className="text-lg font-black text-slate-800 leading-none">{d.getDate()}</span>
                                            </div>
                                            <div className={`flex-1 min-w-0 p-2.5 rounded-xl ${c.bg} group-hover:shadow-sm transition-all`}>
                                                <p className={`font-black text-xs ${c.text} truncate`}>{exam.subject}</p>
                                                <p className="text-[10px] font-bold text-slate-500 mt-0.5">Class {exam.class} · {exam.time}</p>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Detail Modal */}
            {detailEvent && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
                    <div className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm" onClick={() => setDetailEvent(null)} />
                    <div className="bg-white rounded-[2rem] p-8 max-w-sm w-full relative z-10 shadow-2xl border border-slate-100 animate-in zoom-in-95 duration-200">
                        <button
                            onClick={() => setDetailEvent(null)}
                            className="absolute top-5 right-5 p-2 bg-slate-100 hover:bg-slate-200 rounded-xl transition-colors"
                        >
                            <X className="w-4 h-4 text-slate-500" />
                        </button>

                        <div className={`w-14 h-14 ${typeColor(detailEvent.type).bg} rounded-2xl flex items-center justify-center mb-5`}>
                            <GraduationCap className={`w-7 h-7 ${typeColor(detailEvent.type).text}`} />
                        </div>

                        <h3 className="text-2xl font-black text-slate-900 mb-1">{detailEvent.subject}</h3>
                        <span className={`text-[10px] font-black uppercase tracking-widest px-3 py-1 rounded-full ${typeColor(detailEvent.type).bg} ${typeColor(detailEvent.type).text}`}>
                            {detailEvent.type}
                        </span>

                        <div className="mt-6 space-y-4">
                            {[
                                { icon: <CalendarDays className="w-4 h-4" />, label: "Date", value: detailEvent.date },
                                { icon: <Clock className="w-4 h-4" />, label: "Time", value: `${detailEvent.time} (${detailEvent.duration})` },
                                { icon: <Users className="w-4 h-4" />, label: "Class", value: detailEvent.class },
                                { icon: <BookOpen className="w-4 h-4" />, label: "Subject", value: detailEvent.subject },
                            ].map(({ icon, label, value }) => (
                                <div key={label} className="flex items-center gap-4 p-4 bg-slate-50 rounded-2xl">
                                    <div className="text-slate-400">{icon}</div>
                                    <div>
                                        <p className="text-[10px] font-black uppercase tracking-widest text-slate-400">{label}</p>
                                        <p className="font-black text-slate-800 mt-0.5">{value}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
