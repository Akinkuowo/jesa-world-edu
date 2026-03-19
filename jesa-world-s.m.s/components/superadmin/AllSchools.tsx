"use client";

import { useState, useEffect } from "react";
import { Search, School, Trash2, Users, X, UserPlus, Mail, Phone, MapPin, Loader2, RefreshCw, Calendar, AlertTriangle, CheckCircle } from "lucide-react";

interface AllSchoolsProps {
    schools: any[];
    loading: boolean;
    onDelete: (id: string) => void;
    onReactivate: (id: string) => void;
}

export default function AllSchools({ schools, loading, onDelete, onReactivate }: AllSchoolsProps) {
    const [searchQuery, setSearchQuery] = useState("");
    const [selectedSchool, setSelectedSchool] = useState<any>(null);
    const [reactivateConfirm, setReactivateConfirm] = useState<string | null>(null);
    const [showUsersModal, setShowUsersModal] = useState(false);
    const [schoolUsers, setSchoolUsers] = useState<any[]>([]);
    const [loadingUsers, setLoadingUsers] = useState(false);
    const [userRole, setUserRole] = useState<"ADMIN" | "TEACHER" | "STUDENT">("TEACHER");
    const [feedback, setFeedback] = useState<{ type: 'success' | 'error', message: string } | null>(null);

    // User Form State
    const [userData, setUserData] = useState({
        email: "",
        password: "",
        firstName: "",
        lastName: "",
        phone: "",
        address: ""
    });

    const filteredSchools = schools.filter(school =>
        school.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        school.schoolNumber.toLowerCase().includes(searchQuery.toLowerCase()) ||
        school.email.toLowerCase().includes(searchQuery.toLowerCase())
    );

    const fetchSchoolUsers = async (schoolId: string, role: string) => {
        setLoadingUsers(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users/${role}?schoolId=${schoolId}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setSchoolUsers(data);
            }
        } catch (err) {
            console.error("Failed to fetch users", err);
        } finally {
            setLoadingUsers(false);
        }
    };

    useEffect(() => {
        if (selectedSchool) {
            fetchSchoolUsers(selectedSchool.id, userRole);
        }
    }, [userRole, selectedSchool]);

    const handleAddUser = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoadingUsers(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({ ...userData, role: userRole, schoolId: selectedSchool.id })
            });

            if (res.ok) {
                setFeedback({ type: 'success', message: `${userRole} added successfully!` });
                setUserData({ email: "", password: "", firstName: "", lastName: "", phone: "", address: "" });
                fetchSchoolUsers(selectedSchool.id, userRole);
                setTimeout(() => setFeedback(null), 3000);
            } else {
                const data = await res.json();
                setFeedback({ type: 'error', message: data.error || 'Failed to add user' });
            }
        } catch (err) {
            setFeedback({ type: 'error', message: 'Network error' });
        } finally {
            setLoadingUsers(false);
        }
    };

    return (
        <div className="bg-[#11141b] rounded-3xl border border-white/5 overflow-hidden shadow-2xl">
            <div className="p-8 border-b border-white/5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <h2 className="text-xl font-bold text-white">Registered Institutions</h2>
                <div className="relative">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                        type="text"
                        placeholder="Search institutions..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="bg-[#1a1f29] border border-white/5 rounded-xl py-2.5 pl-11 pr-4 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 transition-all w-full md:w-64 text-white"
                    />
                </div>
            </div>

            <div className="overflow-x-auto">
                <table className="w-full text-left">
                    <thead>
                        <tr className="bg-white/2 text-slate-500 text-xs font-bold uppercase tracking-widest border-b border-white/5">
                            <th className="px-8 py-5">Institution</th>
                            <th className="px-8 py-5">School ID</th>
                            <th className="px-8 py-5">Stats</th>
                            <th className="px-8 py-5">Limits</th>
                            <th className="px-8 py-5">Validity</th>
                            <th className="px-8 py-5">Status</th>
                            <th className="px-8 py-5 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                        {loading ? (
                            <tr>
                                <td colSpan={7} className="px-8 py-20 text-center">
                                    <div className="flex flex-col items-center space-y-4">
                                        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                                        <span className="text-slate-500 font-medium">Loading school data...</span>
                                    </div>
                                </td>
                            </tr>
                        ) : filteredSchools.length === 0 ? (
                            <tr>
                                <td colSpan={7} className="px-8 py-20 text-center text-slate-500 italic">
                                    {searchQuery ? "No matching institutions found." : "No schools registered yet."}
                                </td>
                            </tr>
                        ) : filteredSchools.map((school) => (
                            <tr key={school.id} className="hover:bg-white/2 transition-colors group">
                                <td className="px-8 py-6">
                                    <div className="flex items-center space-x-4">
                                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-white font-bold text-lg">
                                            {school.name.charAt(0)}
                                        </div>
                                        <div>
                                            <div className="text-white font-bold">{school.name}</div>
                                            <div className="text-xs text-slate-500">{school.email}</div>
                                        </div>
                                    </div>
                                </td>
                                <td className="px-8 py-6">
                                    <code className="bg-slate-800 text-blue-400 px-3 py-1 rounded-lg font-mono text-sm border border-white/5">{school.schoolNumber}</code>
                                </td>
                                <td className="px-8 py-6">
                                    <div className="flex items-center space-x-1.5 text-xs font-bold">
                                        <Users className="w-3.5 h-3.5 text-slate-500" />
                                        <span className="text-white">{school._count?.users || 0}</span>
                                        <span className="text-slate-500">Users</span>
                                    </div>
                                </td>
                                <td className="px-8 py-6">
                                    <div className="text-sm font-medium">
                                        <span className="text-blue-400">{school.maxStudents}</span> S / <span className="text-indigo-400">{school.maxTeachers}</span> T
                                    </div>
                                </td>
                                <td className="px-8 py-6">
                                    {(() => {
                                        if (!school.validUntil) return <span className="text-slate-500 text-xs">N/A</span>;

                                        const now = new Date();
                                        const validUntil = new Date(school.validUntil);

                                        // Check if date is valid
                                        if (isNaN(validUntil.getTime())) return <span className="text-red-400 text-xs">Invalid Date</span>;

                                        const isExpired = now > validUntil;
                                        const daysRemaining = Math.ceil((validUntil.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

                                        return (
                                            <div className="flex flex-col space-y-1">
                                                <div className="flex items-center space-x-1.5 text-xs font-bold">
                                                    <Calendar className="w-3.5 h-3.5 text-slate-500" />
                                                    <span className={isExpired ? "text-red-400" : daysRemaining < 30 ? "text-amber-400" : "text-emerald-400"}>
                                                        {validUntil.toLocaleDateString()}
                                                    </span>
                                                </div>
                                                <span className="text-[10px] text-slate-600 font-medium">
                                                    {isExpired ? "EXPIRED" : `${daysRemaining} days left`}
                                                </span>
                                            </div>
                                        );
                                    })()}
                                </td>
                                <td className="px-8 py-6">
                                    {(() => {
                                        if (!school.validUntil) return null;

                                        const now = new Date();
                                        const validUntil = new Date(school.validUntil);

                                        if (isNaN(validUntil.getTime())) return null;

                                        const isExpired = now > validUntil;

                                        if (isExpired) {
                                            return (
                                                <span className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-red-500/10 text-red-500 text-xs font-bold border border-red-500/10">
                                                    <AlertTriangle className="w-3 h-3" />
                                                    <span>Expired</span>
                                                </span>
                                            );
                                        }

                                        return (
                                            <span className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-500 text-xs font-bold border border-emerald-500/10">
                                                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                                                <span>Active</span>
                                            </span>
                                        );
                                    })()}
                                </td>
                                <td className="px-8 py-6 text-right">
                                    <div className="flex items-center justify-end space-x-2">
                                        <button
                                            onClick={() => setReactivateConfirm(school.id)}
                                            className="p-2 bg-emerald-600/10 text-emerald-400 hover:bg-emerald-600 hover:text-white rounded-lg transition-all flex items-center space-x-2 px-3 text-xs font-bold"
                                            title="Extend Validity"
                                        >
                                            <RefreshCw className="w-4 h-4" />
                                        </button>
                                        <button
                                            onClick={() => {
                                                setSelectedSchool(school);
                                                setShowUsersModal(true);
                                            }}
                                            className="p-2 bg-blue-600/10 text-blue-400 hover:bg-blue-600 hover:text-white rounded-lg transition-all flex items-center space-x-2 px-3 text-xs font-bold"
                                        >
                                            <Users className="w-4 h-4" />
                                            <span className="hidden md:inline">Manage Users</span>
                                        </button>
                                        <button
                                            onClick={() => onDelete(school.id)}
                                            className="p-2 hover:bg-red-500/10 hover:text-red-500 rounded-lg transition-colors"
                                        >
                                            <Trash2 className="w-4 h-4" />
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Manage Users Modal */}
            {showUsersModal && selectedSchool && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-300">
                    <div className="w-full max-w-5xl bg-[#11141b] rounded-[2.5rem] border border-white/10 shadow-3xl overflow-hidden flex flex-col max-h-[90vh]">
                        {/* Modal Header */}
                        <div className="p-8 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
                            <div className="flex items-center space-x-4">
                                <div className="w-12 h-12 rounded-2xl bg-blue-600 flex items-center justify-center text-white">
                                    <School className="w-6 h-6" />
                                </div>
                                <div>
                                    <h3 className="text-2xl font-black text-white">{selectedSchool.name}</h3>
                                    <p className="text-slate-500 text-sm font-medium">User Management Portal</p>
                                </div>
                            </div>
                            <button
                                onClick={() => setShowUsersModal(false)}
                                className="p-3 hover:bg-white/5 rounded-2xl text-slate-400 hover:text-white transition-all"
                            >
                                <X className="w-6 h-6" />
                            </button>
                        </div>

                        <div className="flex-1 overflow-y-auto p-8 grid lg:grid-cols-2 gap-10">
                            {/* Registration Form */}
                            <div className="space-y-8">
                                <div>
                                    <h4 className="text-lg font-bold text-white mb-2 flex items-center space-x-2">
                                        <UserPlus className="w-5 h-5 text-blue-400" />
                                        <span>Register New Member</span>
                                    </h4>
                                    <p className="text-slate-500 text-sm">Add a new admin, teacher, or student to this institution.</p>
                                </div>

                                <form onSubmit={handleAddUser} className="space-y-5">
                                    <div className="space-y-2">
                                        <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Select Role</label>
                                        <div className="grid grid-cols-3 gap-3">
                                            {(['ADMIN', 'TEACHER', 'STUDENT'] as const).map((r) => (
                                                <button
                                                    key={r}
                                                    type="button"
                                                    onClick={() => setUserRole(r)}
                                                    className={`py-2.5 rounded-xl text-xs font-black transition-all border ${userRole === r
                                                        ? 'bg-blue-600 text-white border-blue-500 shadow-lg shadow-blue-600/20'
                                                        : 'bg-[#1a1f29] text-slate-400 border-white/5 hover:border-white/10'
                                                        }`}
                                                >
                                                    {r}
                                                </button>
                                            ))}
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="text-xs font-black text-slate-500 uppercase tracking-widest">First Name</label>
                                            <input
                                                type="text" required placeholder="John"
                                                value={userData.firstName}
                                                onChange={e => setUserData({ ...userData, firstName: e.target.value })}
                                                className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Last Name</label>
                                            <input
                                                type="text" required placeholder="Doe"
                                                value={userData.lastName}
                                                onChange={e => setUserData({ ...userData, lastName: e.target.value })}
                                                className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                                            />
                                        </div>
                                    </div>

                                    <div className="space-y-2">
                                        <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Email Address</label>
                                        <div className="relative">
                                            <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                                            <input
                                                type="email" required placeholder="member@institution.com"
                                                value={userData.email}
                                                onChange={e => setUserData({ ...userData, email: e.target.value })}
                                                className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 pl-12 text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                                            />
                                        </div>
                                    </div>

                                    <div className="space-y-2">
                                        <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Secure Password</label>
                                        <input
                                            type="password" required placeholder="••••••••"
                                            value={userData.password}
                                            onChange={e => setUserData({ ...userData, password: e.target.value })}
                                            className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                                        />
                                    </div>

                                    {feedback && (
                                        <div className={`p-4 rounded-2xl flex items-center space-x-3 animate-in fade-in slide-in-from-top-2 ${feedback.type === 'success' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/10' : 'bg-red-500/10 text-red-400 border border-red-500/10'
                                            }`}>
                                            <span className="text-sm font-bold">{feedback.message}</span>
                                        </div>
                                    )}

                                    <button
                                        type="submit"
                                        disabled={loadingUsers}
                                        className="w-full bg-blue-600 hover:bg-blue-500 py-4 rounded-2xl text-white font-black shadow-2xl shadow-blue-600/20 active:scale-[0.98] transition-all flex items-center justify-center space-x-3 disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        {loadingUsers ? <Loader2 className="w-5 h-5 animate-spin" /> : <UserPlus className="w-5 h-5" />}
                                        <span>Add {userRole.charAt(0) + userRole.slice(1).toLowerCase()}</span>
                                    </button>
                                </form>
                            </div>

                            {/* User List */}
                            <div className="space-y-8 lg:border-l lg:border-white/5 lg:pl-10">
                                <div className="flex items-center justify-between">
                                    <h4 className="text-lg font-bold text-white flex items-center space-x-2">
                                        <Users className="w-5 h-5 text-indigo-400" />
                                        <span>Current Members</span>
                                    </h4>
                                    <span className="bg-indigo-600/10 text-indigo-400 px-3 py-1 rounded-full text-[10px] font-black tracking-widest uppercase">
                                        {userRole} List
                                    </span>
                                </div>

                                <div className="space-y-4 max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
                                    {loadingUsers && schoolUsers.length === 0 ? (
                                        <div className="flex flex-col items-center justify-center py-20 space-y-4">
                                            <Loader2 className="w-8 h-8 text-slate-700 animate-spin" />
                                            <span className="text-slate-500 font-bold">Fetching members...</span>
                                        </div>
                                    ) : schoolUsers.length === 0 ? (
                                        <div className="text-center py-20 border-2 border-dashed border-white/5 rounded-[2rem]">
                                            <Users className="w-12 h-12 text-slate-800 mx-auto mb-4" />
                                            <p className="text-slate-500 font-medium">No {userRole.toLowerCase()}s recorded yet.</p>
                                        </div>
                                    ) : (
                                        schoolUsers.map((u) => (
                                            <div key={u.id} className="bg-[#1a1f29] border border-white/5 p-5 rounded-2xl hover:border-white/10 transition-all group">
                                                <div className="flex items-center justify-between mb-4">
                                                    <div className="flex items-center space-x-4">
                                                        <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center font-black text-slate-400">
                                                            {u.firstName[0]}{u.lastName[0]}
                                                        </div>
                                                        <div>
                                                            <div className="text-white font-bold">{u.firstName} {u.lastName}</div>
                                                            <div className="text-slate-500 text-xs font-medium">{u.email}</div>
                                                        </div>
                                                    </div>
                                                    <div className={`px-2 py-0.5 rounded-full text-[8px] font-black ${u.isActive ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500'}`}>
                                                        {u.isActive ? 'ACTIVE' : 'INACTIVE'}
                                                    </div>
                                                </div>
                                                <div className="grid grid-cols-2 gap-4 pt-4 border-t border-white/5">
                                                    <div className="flex items-center space-x-2 text-[10px] text-slate-500">
                                                        <Phone className="w-3 h-3" />
                                                        <span>{u.phone || 'N/A'}</span>
                                                    </div>
                                                    <div className="flex items-center space-x-2 text-[10px] text-slate-500">
                                                        <MapPin className="w-3 h-3" />
                                                        <span className="truncate">{u.address || 'N/A'}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        ))
                                    )}
                                </div>
                            </div>
                        </div>

                        {/* Modal Footer */}
                        <div className="p-6 bg-white/[0.02] border-t border-white/5 text-center">
                            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-[0.2em]">
                                JESA World School Management System &copy; 2026
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {/* Reactivate Confirmation Modal */}
            {reactivateConfirm && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
                    <div className="w-full max-w-md bg-[#11141b] rounded-2xl border border-white/10 p-8 shadow-2xl">
                        <div className="w-12 h-12 bg-emerald-500/10 rounded-xl flex items-center justify-center mb-6 border border-emerald-500/20">
                            <RefreshCw className="w-6 h-6 text-emerald-500" />
                        </div>
                        <h3 className="text-xl font-bold text-white mb-2">Confirm Reactivation</h3>
                        <p className="text-slate-400 mb-6 text-sm">
                            Are you sure you want to reactivate this school?
                            <br /><br />
                            This will extend their validity period by <strong>4 months</strong> from today.
                        </p>
                        <div className="flex justify-end space-x-4">
                            <button onClick={() => setReactivateConfirm(null)} className="px-5 py-2.5 rounded-xl hover:bg-white/5 transition-colors font-semibold text-sm">Cancel</button>
                            <button
                                onClick={() => {
                                    onReactivate(reactivateConfirm);
                                    setReactivateConfirm(null);
                                }}
                                className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-white font-bold transition-all text-sm shadow-lg shadow-emerald-500/20"
                            >
                                Confirm Reactivation
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
