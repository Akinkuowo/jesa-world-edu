"use client";

import { useState, useEffect } from "react";
import {
    School,
    User,
    Mail,
    Phone,
    MapPin,
    Lock,
    Save,
    Loader2,
    Shield,
    Image as ImageIcon
} from "lucide-react";

export default function SettingsView() {
    const [activeTab, setActiveTab] = useState<'SCHOOL' | 'ACCOUNT'>('SCHOOL');
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [feedback, setFeedback] = useState<{ type: 'success' | 'error', message: string } | null>(null);

    const [schoolForm, setSchoolForm] = useState({
        name: "",
        address: "",
        phone: "",
        email: ""
    });

    const [accountForm, setAccountForm] = useState({
        firstName: "",
        lastName: "",
        email: "",
        phone: "",
        address: ""
    });

    const [passwordForm, setPasswordForm] = useState({
        currentPassword: "",
        newPassword: "",
        confirmPassword: ""
    });

    const fetchSettings = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const [schoolRes, accountRes] = await Promise.all([
                fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/school`, { headers: { Authorization: `Bearer ${token}` } }),
                fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/profile`, { headers: { Authorization: `Bearer ${token}` } })
            ]);

            if (schoolRes.ok) setSchoolForm(await schoolRes.json());
            if (accountRes.ok) setAccountForm(await accountRes.json());
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchSettings();
    }, []);

    const handleSchoolSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/school`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(schoolForm)
            });

            if (res.ok) {
                setFeedback({ type: 'success', message: "School details updated successfully!" });
            } else {
                setFeedback({ type: 'error', message: "Failed to update school details" });
            }
        } catch (err) {
            setFeedback({ type: 'error', message: "Network error" });
        } finally {
            setSaving(false);
            setTimeout(() => setFeedback(null), 3000);
        }
    };

    const handleAccountSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/profile`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(accountForm)
            });

            if (res.ok) {
                setFeedback({ type: 'success', message: "Account profile updated successfully!" });
            } else {
                setFeedback({ type: 'error', message: "Failed to update profile" });
            }
        } catch (err) {
            setFeedback({ type: 'error', message: "Network error" });
        } finally {
            setSaving(false);
            setTimeout(() => setFeedback(null), 3000);
        }
    };

    const handlePasswordSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (passwordForm.newPassword !== passwordForm.confirmPassword) {
            setFeedback({ type: 'error', message: "Passwords do not match" });
            return;
        }

        setSaving(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/change-password`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    currentPassword: passwordForm.currentPassword,
                    newPassword: passwordForm.newPassword
                })
            });

            if (res.ok) {
                setFeedback({ type: 'success', message: "Password updated successfully!" });
                setPasswordForm({ currentPassword: "", newPassword: "", confirmPassword: "" });
            } else {
                const data = await res.json();
                setFeedback({ type: 'error', message: data.error || "Failed to update password" });
            }
        } catch (err) {
            setFeedback({ type: 'error', message: "Network error" });
        } finally {
            setSaving(false);
            setTimeout(() => setFeedback(null), 3000);
        }
    };

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center p-20 text-slate-400">
                <Loader2 className="w-10 h-10 animate-spin mb-4" />
                <p className="font-bold">Loading settings...</p>
            </div>
        );
    }

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {feedback && (
                <div className={`fixed top-8 right-8 px-6 py-3 rounded-2xl text-white font-bold text-sm shadow-lg z-[60] animate-in slide-in-from-top duration-300 ${feedback.type === 'success' ? 'bg-emerald-500' : 'bg-red-500'}`}>
                    {feedback.message}
                </div>
            )}

            {/* Navigation Tabs */}
            <div className="flex items-center space-x-1 bg-white p-1.5 rounded-2xl border border-slate-200 w-fit shadow-sm">
                <button
                    onClick={() => setActiveTab('SCHOOL')}
                    className={`px-6 py-2 rounded-xl text-sm font-bold transition-all ${activeTab === 'SCHOOL' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20' : 'text-slate-500 hover:bg-slate-50'}`}
                >
                    School Profile
                </button>
                <button
                    onClick={() => setActiveTab('ACCOUNT')}
                    className={`px-6 py-2 rounded-xl text-sm font-bold transition-all ${activeTab === 'ACCOUNT' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20' : 'text-slate-500 hover:bg-slate-50'}`}
                >
                    Account Settings
                </button>
            </div>

            {activeTab === 'SCHOOL' ? (
                <div className="grid lg:grid-cols-3 gap-8">
                    <div className="lg:col-span-2 bg-white rounded-[2rem] border border-slate-200 p-10 shadow-sm">
                        <div className="flex items-center space-x-4 mb-10">
                            <div className="bg-indigo-50 p-4 rounded-3xl">
                                <School className="w-8 h-8 text-indigo-600" />
                            </div>
                            <div>
                                <h2 className="text-2xl font-black text-slate-900">School Information</h2>
                                <p className="text-sm text-slate-500 font-medium">Update public details about your institution.</p>
                            </div>
                        </div>

                        <form onSubmit={handleSchoolSubmit} className="space-y-6">
                            <div className="grid md:grid-cols-2 gap-6">
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">School Name</label>
                                    <input
                                        required
                                        type="text"
                                        value={schoolForm.name}
                                        onChange={e => setSchoolForm({ ...schoolForm, name: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Office Email</label>
                                    <input
                                        required
                                        type="email"
                                        value={schoolForm.email}
                                        onChange={e => setSchoolForm({ ...schoolForm, email: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                            </div>

                            <div className="grid md:grid-cols-2 gap-6">
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Contact Phone</label>
                                    <input
                                        type="text"
                                        value={schoolForm.phone}
                                        onChange={e => setSchoolForm({ ...schoolForm, phone: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Address</label>
                                    <input
                                        type="text"
                                        value={schoolForm.address}
                                        onChange={e => setSchoolForm({ ...schoolForm, address: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                            </div>

                            <button
                                type="submit"
                                disabled={saving}
                                className="flex items-center space-x-2 bg-indigo-600 text-white py-4 px-8 rounded-2xl font-black hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-600/20"
                            >
                                {saving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5" />}
                                <span>Save Changes</span>
                            </button>
                        </form>
                    </div>

                    <div className="space-y-8">
                        <div className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm">
                            <h3 className="text-lg font-black text-slate-900 mb-6">Logo & Branding</h3>
                            <div className="bg-slate-50 border-2 border-dashed border-slate-200 rounded-3xl p-10 text-center group cursor-pointer hover:border-indigo-300 transition-all">
                                <div className="w-20 h-20 bg-white rounded-2xl shadow-sm flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform">
                                    <ImageIcon className="w-8 h-8 text-slate-300 group-hover:text-indigo-600" />
                                </div>
                                <p className="text-xs font-bold text-slate-400">Click to upload school logo</p>
                            </div>
                        </div>

                        <div className="bg-indigo-600 rounded-[2rem] p-8 text-white shadow-xl shadow-indigo-600/20 relative overflow-hidden">
                            <div className="absolute -right-4 -top-4 w-32 h-32 bg-white/10 rounded-full" />
                            <Shield className="w-10 h-10 mb-6 opacity-80" />
                            <h3 className="text-lg font-black mb-2">Security Note</h3>
                            <p className="text-sm text-indigo-100 opacity-80 leading-relaxed">Ensure school contact information is kept up to date for official communications and system alerts.</p>
                        </div>
                    </div>
                </div>
            ) : (
                <div className="grid lg:grid-cols-3 gap-8">
                    <div className="lg:col-span-2 space-y-8">
                        <div className="bg-white rounded-[2rem] border border-slate-200 p-10 shadow-sm">
                            <div className="flex items-center space-x-4 mb-10">
                                <div className="bg-emerald-50 p-4 rounded-3xl">
                                    <User className="w-8 h-8 text-emerald-600" />
                                </div>
                                <div>
                                    <h2 className="text-2xl font-black text-slate-900">Personal Profile</h2>
                                    <p className="text-sm text-slate-500 font-medium">Update your account information.</p>
                                </div>
                            </div>

                            <form onSubmit={handleAccountSubmit} className="space-y-6">
                                <div className="grid md:grid-cols-2 gap-6">
                                    <div className="space-y-2">
                                        <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">First Name</label>
                                        <input
                                            required
                                            type="text"
                                            value={accountForm.firstName}
                                            onChange={e => setAccountForm({ ...accountForm, firstName: e.target.value })}
                                            className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Last Name</label>
                                        <input
                                            required
                                            type="text"
                                            value={accountForm.lastName}
                                            onChange={e => setAccountForm({ ...accountForm, lastName: e.target.value })}
                                            className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                                        />
                                    </div>
                                </div>

                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Email Address</label>
                                    <input
                                        required
                                        type="email"
                                        value={accountForm.email}
                                        onChange={e => setAccountForm({ ...accountForm, email: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                                    />
                                </div>

                                <div className="grid md:grid-cols-2 gap-6">
                                    <div className="space-y-2">
                                        <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Phone Number</label>
                                        <input
                                            type="text"
                                            value={accountForm.phone}
                                            onChange={e => setAccountForm({ ...accountForm, phone: e.target.value })}
                                            className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Address</label>
                                        <input
                                            type="text"
                                            value={accountForm.address}
                                            onChange={e => setAccountForm({ ...accountForm, address: e.target.value })}
                                            className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                                        />
                                    </div>
                                </div>

                                <button
                                    type="submit"
                                    disabled={saving}
                                    className="flex items-center space-x-2 bg-emerald-600 text-white py-4 px-8 rounded-2xl font-black hover:bg-emerald-700 transition-all shadow-lg shadow-emerald-600/20"
                                >
                                    {saving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5" />}
                                    <span>Update Profile</span>
                                </button>
                            </form>
                        </div>

                        <div className="bg-white rounded-[2rem] border border-slate-200 p-10 shadow-sm">
                            <div className="flex items-center space-x-4 mb-10">
                                <div className="bg-red-50 p-3 rounded-2xl">
                                    <Lock className="w-6 h-6 text-red-600" />
                                </div>
                                <h2 className="text-xl font-black text-slate-900">Change Password</h2>
                            </div>

                            <form onSubmit={handlePasswordSubmit} className="max-w-md space-y-6">
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Current Password</label>
                                    <input
                                        required
                                        type="password"
                                        value={passwordForm.currentPassword}
                                        onChange={e => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-red-500/20"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">New Password</label>
                                    <input
                                        required
                                        type="password"
                                        value={passwordForm.newPassword}
                                        onChange={e => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-red-500/20"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Confirm New Password</label>
                                    <input
                                        required
                                        type="password"
                                        value={passwordForm.confirmPassword}
                                        onChange={e => setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-red-500/20"
                                    />
                                </div>
                                <button
                                    type="submit"
                                    disabled={saving}
                                    className="w-full bg-red-600 text-white py-4 px-8 rounded-2xl font-black hover:bg-red-700 transition-all shadow-lg shadow-red-600/20 flex items-center justify-center space-x-2"
                                >
                                    {saving ? <Loader2 className="w-5 h-5 animate-spin" /> : <span>Update Password</span>}
                                </button>
                            </form>
                        </div>
                    </div>

                    <div className="space-y-8">
                        <div className="bg-slate-900 rounded-[2rem] p-8 text-white shadow-xl shadow-slate-900/20">
                            <h3 className="text-lg font-black mb-4">Account Security</h3>
                            <div className="space-y-4">
                                <SecurityItem label="Two-Factor Auth" status="Disabled" />
                                <SecurityItem label="Last Login" status="Today, 10:45 AM" />
                                <SecurityItem label="Active Sessions" status="2 Devices" />
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

function SecurityItem({ label, status }: { label: string, status: string }) {
    return (
        <div className="flex items-center justify-between border-b border-white/10 pb-4 last:border-0 last:pb-0">
            <span className="text-xs font-bold text-slate-400">{label}</span>
            <span className="text-xs font-black text-white">{status}</span>
        </div>
    );
}
