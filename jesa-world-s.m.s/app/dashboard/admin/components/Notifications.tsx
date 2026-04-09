"use client";

import { useState, useEffect } from "react";
import toast from "react-hot-toast";
import {
    Bell,
    Send,
    History,
    Trash2,
    Loader2,
    Plus,
    X,
    Megaphone,
    Search,
    AlertTriangle,
    CheckCircle2
} from "lucide-react";

export default function Notifications() {
    const [activeTab, setActiveTab] = useState<'SEND' | 'HISTORY'>('SEND');

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Navigation Tabs */}
            <div className="flex items-center space-x-1 bg-white p-1.5 rounded-2xl border border-slate-200 w-fit shadow-sm">
                <button
                    onClick={() => setActiveTab('SEND')}
                    className={`px-6 py-2 rounded-xl text-sm font-bold transition-all flex items-center space-x-2 ${activeTab === 'SEND' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20' : 'text-slate-500 hover:bg-slate-50'}`}
                >
                    <Plus className="w-4 h-4" />
                    <span>Send Notification</span>
                </button>
                <button
                    onClick={() => setActiveTab('HISTORY')}
                    className={`px-6 py-2 rounded-xl text-sm font-bold transition-all flex items-center space-x-2 ${activeTab === 'HISTORY' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20' : 'text-slate-500 hover:bg-slate-50'}`}
                >
                    <History className="w-4 h-4" />
                    <span>Sent History</span>
                </button>
            </div>

            {/* Content based on tab */}
            {activeTab === 'SEND' && <SendNotificationView />}
            {activeTab === 'HISTORY' && <NotificationHistoryView />}
        </div>
    );
}

function SendNotificationView() {
    const [loading, setLoading] = useState(false);
    const [form, setForm] = useState({
        title: "",
        message: "",
        type: "INFO",
        target: "TEACHER"
    });

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/notifications`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(form)
            });

            if (res.ok) {
                toast.success("Notification sent successfully!");
                setForm({ title: "", message: "", type: "INFO", target: "TEACHER" });
            } else {
                const data = await res.json();
                toast.error(data.error || "Failed to send notification");
            }
        } catch (err) {
            toast.error("Network error");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm">
            <div className="flex items-center space-x-4 mb-8">
                <div className="w-12 h-12 bg-indigo-50 rounded-2xl flex items-center justify-center text-indigo-600 shadow-sm border border-indigo-100">
                    <Megaphone className="w-6 h-6" />
                </div>
                <div>
                    <h2 className="text-xl font-black text-slate-900">Broadcast Message</h2>
                    <p className="text-sm text-slate-500 font-medium">Send announcements or reminders to school staff and students.</p>
                </div>
            </div>

            <form onSubmit={handleSubmit} className="max-w-2xl space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                        <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Notification Type</label>
                        <select
                            value={form.type}
                            onChange={e => setForm({...form, type: e.target.value})}
                            className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                        >
                            <option value="INFO">General Information</option>
                            <option value="EXAM_REMINDER">Exam Reminder</option>
                            <option value="URGENT">Urgent Announcement</option>
                        </select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Target Audience</label>
                        <select
                            value={form.target}
                            onChange={e => setForm({...form, target: e.target.value})}
                            className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                        >
                            <option value="TEACHER">All Teachers</option>
                            <option value="STUDENT">All Students</option>
                            <option value="ADMIN">Other School Admins</option>
                        </select>
                    </div>
                </div>

                <div className="space-y-2">
                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Title</label>
                    <input
                        required
                        type="text"
                        placeholder="e.g. Mid-term Exam Reminder"
                        value={form.title}
                        onChange={e => setForm({...form, title: e.target.value})}
                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                    />
                </div>

                <div className="space-y-2">
                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Message Content</label>
                    <textarea
                        required
                        rows={4}
                        placeholder="Type your message here..."
                        value={form.message}
                        onChange={e => setForm({...form, message: e.target.value})}
                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20 resize-none"
                    />
                </div>

                <button
                    type="submit"
                    disabled={loading}
                    className="w-full bg-indigo-600 text-white p-4 rounded-2xl font-black hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-600/20 flex items-center justify-center space-x-2"
                >
                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : (
                        <>
                            <span>Broadcast Now</span>
                            <Send className="w-4 h-4 ml-2" />
                        </>
                    )}
                </button>
            </form>
        </div>
    );
}

function NotificationHistoryView() {
    const [notifications, setNotifications] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);

    const fetchHistory = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/notifications`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) setNotifications(await res.json());
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm("Are you sure you want to delete this notification history? This will remove it from recipient dashboards.")) return;
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/notifications/${id}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                toast.success("Notification deleted");
                setNotifications(notifications.filter(n => n.id !== id));
            }
        } catch (err) {
            toast.error("Action failed");
        }
    };

    useEffect(() => {
        fetchHistory();
    }, []);

    return (
        <div className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h2 className="text-xl font-black text-slate-900">Broadcast History</h2>
                    <p className="text-sm text-slate-500 font-medium">Recent announcements sent from this school.</p>
                </div>
                <button
                    onClick={fetchHistory}
                    className="p-2.5 bg-slate-50 hover:bg-slate-100 rounded-xl text-slate-400 transition-colors"
                >
                    <Search className="w-5 h-5" />
                </button>
            </div>

            {loading ? (
                <div className="flex flex-col items-center justify-center py-20 text-slate-400">
                    <Loader2 className="w-8 h-8 animate-spin mb-4" />
                    <p className="font-bold">Loading history...</p>
                </div>
            ) : notifications.length === 0 ? (
                <div className="text-center py-20 border-2 border-dashed border-slate-100 rounded-[2rem]">
                    <Bell className="w-12 h-12 text-slate-200 mx-auto mb-4" />
                    <p className="text-slate-400 font-bold">No notifications sent yet.</p>
                </div>
            ) : (
                <div className="space-y-4">
                    {notifications.map(n => (
                        <div key={n.id} className="p-6 bg-slate-50 border border-slate-100 rounded-3xl flex items-start gap-4 group hover:bg-white hover:border-indigo-200 transition-all">
                            <div className={`p-3 rounded-2xl shadow-sm bg-white ${
                                n.type === 'EXAM_REMINDER' ? 'text-amber-600' : 
                                n.type === 'URGENT' ? 'text-red-500' : 'text-indigo-600'
                                }`}>
                                {n.type === 'EXAM_REMINDER' ? <AlertTriangle className="w-5 h-5" /> : 
                                 n.type === 'URGENT' ? <AlertTriangle className="w-5 h-5" /> : <Bell className="w-5 h-5" />}
                            </div>
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center justify-between">
                                    <h3 className="text-base font-black text-slate-900 truncate">{n.title}</h3>
                                    <button
                                        onClick={() => handleDelete(n.id)}
                                        className="opacity-0 group-hover:opacity-100 p-2 text-slate-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-all"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                                <p className="text-sm text-slate-600 font-medium mt-1 leading-relaxed line-clamp-2">{n.message}</p>
                                <div className="flex items-center space-x-3 mt-4">
                                    <span className="text-[10px] font-black uppercase tracking-wider bg-slate-200 px-2 py-0.5 rounded-md text-slate-600">To: {n.target}s</span>
                                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{new Date(n.createdAt).toLocaleString()}</span>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
