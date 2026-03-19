"use client";

import { useState, useEffect } from "react";
import { User, Lock, Mail, ShieldCheck, Loader2, Save, AlertCircle, CheckCircle2 } from "lucide-react";

export default function SuperAdminSettings() {
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [feedback, setFeedback] = useState<{ type: 'success' | 'error', message: string } | null>(null);

    const [profile, setProfile] = useState({
        firstName: "",
        lastName: "",
        email: ""
    });

    const [passwordData, setPasswordData] = useState({
        currentPassword: "",
        newPassword: "",
        confirmPassword: ""
    });

    const fetchProfile = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/superadmin/profile`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setProfile({
                    firstName: data.firstName || "",
                    lastName: data.lastName || "",
                    email: data.email || ""
                });
            }
        } catch (err) {
            console.error("Failed to fetch profile", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchProfile();
    }, []);

    const handleUpdateProfile = async (e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        setFeedback(null);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/superadmin/profile`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(profile)
            });

            if (res.ok) {
                setFeedback({ type: 'success', message: "Profile updated successfully!" });
                // Update local storage user data if needed
                const user = JSON.parse(localStorage.getItem("user") || "{}");
                localStorage.setItem("user", JSON.stringify({ ...user, ...profile }));
            } else {
                setFeedback({ type: 'error', message: "Failed to update profile." });
            }
        } catch (err) {
            setFeedback({ type: 'error', message: "Network error." });
        } finally {
            setSaving(false);
        }
    };

    const handleChangePassword = async (e: React.FormEvent) => {
        e.preventDefault();
        if (passwordData.newPassword !== passwordData.confirmPassword) {
            setFeedback({ type: 'error', message: "Passwords do not match." });
            return;
        }

        setSaving(true);
        setFeedback(null);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/superadmin/change-password`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    currentPassword: passwordData.currentPassword,
                    newPassword: passwordData.newPassword
                })
            });

            if (res.ok) {
                setFeedback({ type: 'success', message: "Password updated successfully!" });
                setPasswordData({ currentPassword: "", newPassword: "", confirmPassword: "" });
            } else {
                const data = await res.json();
                setFeedback({ type: 'error', message: data.error || "Failed to change password." });
            }
        } catch (err) {
            setFeedback({ type: 'error', message: "Network error." });
        } finally {
            setSaving(false);
        }
    };

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center py-20 space-y-4">
                <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
                <span className="text-slate-500 font-bold uppercase tracking-widest text-xs">Loading Settings...</span>
            </div>
        );
    }

    return (
        <div className="max-w-4xl space-y-10 animate-in fade-in duration-500">
            {feedback && (
                <div className={`p-4 rounded-2xl flex items-center space-x-3 border ${feedback.type === 'success'
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/10'
                        : 'bg-red-500/10 text-red-400 border-red-500/10'
                    }`}>
                    {feedback.type === 'success' ? <CheckCircle2 className="w-5 h-5" /> : <AlertCircle className="w-5 h-5" />}
                    <span className="font-bold text-sm">{feedback.message}</span>
                </div>
            )}

            <div className="grid lg:grid-cols-2 gap-10">
                {/* Profile Section */}
                <div className="bg-[#11141b] rounded-[2.5rem] border border-white/5 p-8 shadow-2xl space-y-8">
                    <div>
                        <h2 className="text-xl font-black text-white flex items-center space-x-3">
                            <User className="w-6 h-6 text-blue-500" />
                            <span>Personal Profile</span>
                        </h2>
                        <p className="text-slate-500 text-sm mt-2">Manage your public information and master email.</p>
                    </div>

                    <form onSubmit={handleUpdateProfile} className="space-y-6">
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">First Name</label>
                                <input
                                    type="text"
                                    value={profile.firstName}
                                    onChange={e => setProfile({ ...profile, firstName: e.target.value })}
                                    className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                                />
                            </div>
                            <div className="space-y-2">
                                <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Last Name</label>
                                <input
                                    type="text"
                                    value={profile.lastName}
                                    onChange={e => setProfile({ ...profile, lastName: e.target.value })}
                                    className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Master Email</label>
                            <div className="relative group">
                                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600 transition-colors group-focus-within:text-blue-500" />
                                <input
                                    type="email"
                                    value={profile.email}
                                    onChange={e => setProfile({ ...profile, email: e.target.value })}
                                    className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 pl-12 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                                />
                            </div>
                        </div>

                        <button
                            type="submit"
                            disabled={saving}
                            className="w-full bg-blue-600 hover:bg-blue-500 py-4 rounded-2xl text-white font-black shadow-2xl shadow-blue-600/20 flex items-center justify-center space-x-3 transition-all active:scale-[0.98] disabled:opacity-50"
                        >
                            {saving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5" />}
                            <span>Update Profile</span>
                        </button>
                    </form>
                </div>

                {/* Security Section */}
                <div className="bg-[#11141b] rounded-[2.5rem] border border-white/5 p-8 shadow-2xl space-y-8">
                    <div>
                        <h2 className="text-xl font-black text-white flex items-center space-x-3">
                            <ShieldCheck className="w-6 h-6 text-indigo-500" />
                            <span>Security & Access</span>
                        </h2>
                        <p className="text-slate-500 text-sm mt-2">Update your master password regularly for security.</p>
                    </div>

                    <form onSubmit={handleChangePassword} className="space-y-5">
                        <div className="space-y-2">
                            <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Current Password</label>
                            <input
                                type="password"
                                required
                                value={passwordData.currentPassword}
                                onChange={e => setPasswordData({ ...passwordData, currentPassword: e.target.value })}
                                className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                                placeholder="••••••••"
                            />
                        </div>
                        <div className="space-y-2">
                            <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">New Password</label>
                            <input
                                type="password"
                                required
                                value={passwordData.newPassword}
                                onChange={e => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                                className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                                placeholder="••••••••"
                            />
                        </div>
                        <div className="space-y-2">
                            <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Confirm New Password</label>
                            <input
                                type="password"
                                required
                                value={passwordData.confirmPassword}
                                onChange={e => setPasswordData({ ...passwordData, confirmPassword: e.target.value })}
                                className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                                placeholder="••••••••"
                            />
                        </div>

                        <button
                            type="submit"
                            disabled={saving}
                            className="w-full bg-[#1a1f29] border border-white/5 hover:bg-white/5 py-4 rounded-2xl text-white font-black transition-all active:scale-[0.98] disabled:opacity-50 flex items-center justify-center space-x-3"
                        >
                            {saving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Lock className="w-5 h-5" />}
                            <span>Change Password</span>
                        </button>
                    </form>
                </div>
            </div>

            {/* System Info */}
            <div className="bg-[#11141b] rounded-[1.5rem] border border-white/5 p-6 flex flex-col md:flex-row items-center justify-between opacity-60">
                <div className="flex items-center space-x-4 mb-4 md:mb-0">
                    <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                    <span className="text-sm font-bold text-slate-400 capitalize tracking-widest">System Status: Optimal</span>
                </div>
                <div className="text-[10px] font-black text-slate-600 uppercase tracking-[0.3em]">
                    JESA WORLD SMS v1.0.4 • ENCRYPTED SESSION
                </div>
            </div>
        </div>
    );
}
