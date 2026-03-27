"use client";

import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import {
    Users,
    School,
    Plus,
    Trash2,
    Search,
    Settings,
    LogOut,
    LayoutDashboard,
    ShieldCheck,
    TrendingUp,
    Activity
} from "lucide-react";
import { useRouter } from "next/navigation";
import Image from "next/image";
import AllSchools from "@/components/superadmin/AllSchools";
import AllAdmins from "@/components/superadmin/AllAdmins";
import SuperAdminSettings from "@/components/superadmin/SuperAdminSettings";

export default function SuperAdminDashboard() {
    const router = useRouter();
    const [schools, setSchools] = useState<any[]>([]);
    const [admins, setAdmins] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [showAddModal, setShowAddModal] = useState(false);
    const [newSchool, setNewSchool] = useState({
        name: "",
        email: "",
        address: "",
        phone: "",
        maxStudents: 100,
        maxTeachers: 10,
        adminEmail: "",
        adminPassword: "",
        adminFirstName: "",
        adminLastName: ""
    });
    const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
    const [activeView, setActiveView] = useState<'OVERVIEW' | 'SCHOOLS' | 'ADMINS' | 'SETTINGS'>('OVERVIEW');

    const fetchSchools = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/superadmin/schools`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = await res.json();

            if (Array.isArray(data)) {
                setSchools(data);
            } else {
                console.error("Expected an array of schools, but got:", data);
                setSchools([]);
                if (res.status === 401 || res.status === 403) {
                    router.push("/login");
                }
            }
        } catch (err) {
            console.error(err);
            setSchools([]);
        } finally {
            setLoading(false);
        }
    };

    const fetchAdmins = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/superadmin/admins`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = await res.json();
            if (Array.isArray(data)) {
                setAdmins(data);
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (activeView === 'OVERVIEW' || activeView === 'SCHOOLS') {
            fetchSchools();
        } else if (activeView === 'ADMINS') {
            fetchAdmins();
        }
    }, [activeView]);

    const handleCreateSchool = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/superadmin/schools`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(newSchool)
            });
            if (res.ok) {
                setShowAddModal(false);
                toast.success('School created successfully!');
                fetchSchools();
            } else {
                const data = await res.json();
                toast.error(data.error || 'Failed to create school');
            }
        } catch (err) {
            toast.error('Network error. Please try again.');
            console.error(err);
        }
    };

    const handleReactivateSchool = async (schoolId: string) => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/superadmin/schools/${schoolId}/reactivate`, {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                toast.success('School reactivated successfully for 4 months!');
                fetchSchools();
            } else {
                toast.error('Failed to reactivate school');
            }
        } catch (err) {
            toast.error('Network error during reactivation.');
        }
    };

    const handleDeleteSchool = async (schoolId: string) => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/superadmin/schools/${schoolId}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                toast.success('School deleted successfully!');
                fetchSchools();
            } else {
                toast.error('Failed to delete school');
            }
        } catch (err) {
            toast.error('Network error during deletion.');
        }
        setDeleteConfirm(null);
    };

    const handleLogout = () => {
        localStorage.clear();
        router.push("/superadmin");
    };

    return (
        <div className="min-h-screen bg-[#0a0c10] text-slate-300 font-sans">
            {/* Sidebar */}
            <aside className="fixed left-0 top-0 h-full w-72 bg-[#11141b] border-r border-white/5 z-20 hidden lg:flex flex-col">
                <div className="p-8 border-b border-white/5">
                    <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center shadow-lg shadow-blue-500/10">
                            <School className="w-6 h-6 text-white" />
                        </div>
                        <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">JESA World</span>
                    </div>
                </div>

                <nav className="flex-1 p-6 space-y-2">
                    <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-4 px-3">Main Menu</div>
                    <button
                        onClick={() => setActiveView('OVERVIEW')}
                        className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition-all border ${activeView === 'OVERVIEW' ? 'bg-blue-600/10 text-blue-400 border-blue-500/10' : 'text-slate-400 hover:bg-white/5 hover:text-white border-transparent'}`}
                    >
                        <LayoutDashboard className="w-5 h-5" />
                        <span className="font-medium">Overview</span>
                    </button>
                    <button
                        onClick={() => setActiveView('SCHOOLS')}
                        className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition-all border ${activeView === 'SCHOOLS' ? 'bg-blue-600/10 text-blue-400 border-blue-500/10' : 'text-slate-400 hover:bg-white/5 hover:text-white border-transparent'}`}
                    >
                        <School className="w-5 h-5" />
                        <span className="font-medium">All Schools</span>
                    </button>
                    <button
                        onClick={() => setActiveView('ADMINS')}
                        className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition-all border ${activeView === 'ADMINS' ? 'bg-blue-600/10 text-blue-400 border-blue-500/10' : 'text-slate-400 hover:bg-white/5 hover:text-white border-transparent'}`}
                    >
                        <Users className="w-5 h-5" />
                        <span className="font-medium">Administrators</span>
                    </button>
                    <div className="pt-8">
                        <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-4 px-3">System</div>
                        <button
                            onClick={() => setActiveView('SETTINGS')}
                            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition-all border ${activeView === 'SETTINGS' ? 'bg-blue-600/10 text-blue-400 border-blue-500/10' : 'text-slate-400 hover:bg-white/5 hover:text-white border-transparent'}`}
                        >
                            <Settings className="w-5 h-5" />
                            <span className="font-medium">Settings</span>
                        </button>
                        <button onClick={handleLogout} className="w-full flex items-center space-x-3 px-4 py-3 hover:bg-red-500/10 hover:text-red-400 rounded-xl transition-all mt-4">
                            <LogOut className="w-5 h-5" />
                            <span className="font-medium">Sign Out</span>
                        </button>
                    </div>
                </nav>

                <div className="p-6">
                    <div className="bg-[#1a1f29] rounded-2xl p-4 border border-white/5">
                        <div className="flex items-center space-x-3 mb-3">
                            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                            <span className="text-sm font-medium text-emerald-500">System Healthy</span>
                        </div>
                        <p className="text-xs text-slate-500">v1.0.4 - All services running optimally.</p>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="lg:ml-72 p-8">
                {/* Header */}
                <header className="flex flex-col md:flex-row md:items-center justify-between mb-12 gap-6">
                    <div>
                        <h1 className="text-4xl font-extrabold text-white tracking-tight mb-2">
                            {activeView === 'OVERVIEW' ? 'Super Admin Dashboard' : activeView === 'SCHOOLS' ? 'All Registered Schools' : activeView === 'ADMINS' ? 'System Administrators' : 'Account Settings'}
                        </h1>
                        <p className="text-slate-500 text-lg">
                            {activeView === 'OVERVIEW'
                                ? 'Central control for all registered educational institutions.'
                                : activeView === 'SCHOOLS'
                                    ? 'Manage and monitor all institutions within the platform.'
                                    : activeView === 'ADMINS'
                                        ? 'Manage and monitor all school administrators across the system.'
                                        : 'Update your profile and account security settings.'}
                        </p>
                    </div>
                    <button
                        onClick={() => setShowAddModal(true)}
                        className="bg-blue-600 hover:bg-blue-500 py-3.5 px-6 rounded-2xl text-white font-bold flex items-center justify-center space-x-3 shadow-2xl shadow-blue-600/20 active:scale-95 transition-all w-full md:w-auto"
                    >
                        <Plus className="w-5 h-5" />
                        <span>Add New School</span>
                    </button>
                </header>


                {/* Content View */}
                {activeView === 'OVERVIEW' ? (
                    <>
                        {/* Stats Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                            <StatCard
                                title="Total Schools"
                                value={loading ? "..." : (Array.isArray(schools) ? schools.length.toString() : "0")}
                                icon={<School className="w-6 h-6" />}
                                color="blue"
                            />
                            <StatCard title="Total Users" value="1,284" icon={<Users className="w-6 h-6" />} color="indigo" />
                            <StatCard title="Active Subs" value="98%" icon={<Activity className="w-6 h-6" />} color="emerald" />
                            <StatCard title="Revenue Growth" value="+24%" icon={<TrendingUp className="w-6 h-6" />} color="amber" />
                        </div>
                    </>
                ) : activeView === 'SCHOOLS' ? (
                    <AllSchools
                        schools={schools}
                        loading={loading}
                        onDelete={(id) => setDeleteConfirm(id)}
                        onReactivate={handleReactivateSchool}
                    />
                ) : activeView === 'ADMINS' ? (
                    <AllAdmins
                        admins={admins}
                        loading={loading}
                    />
                ) : (
                    <SuperAdminSettings />
                )}
            </main>

            {/* Modal - Not implemented for brevity but indicated in UI */}
            {showAddModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-300">
                    <div className="w-full max-w-2xl bg-[#11141b] rounded-[2rem] border border-white/10 p-10 shadow-3xl">
                        <h2 className="text-2xl font-bold text-white mb-8">Add New Educational Institution</h2>
                        <form onSubmit={handleCreateSchool} className="space-y-6">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-slate-400">School Name</label>
                                    <input type="text" required placeholder="e.g. Cambridge Academy" className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20" onChange={e => setNewSchool({ ...newSchool, name: e.target.value })} />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-slate-400">Official Email</label>
                                    <input type="email" required placeholder="admin@school.com" className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20" onChange={e => setNewSchool({ ...newSchool, email: e.target.value })} />
                                </div>
                            </div>

                            <div className="p-6 bg-blue-600/5 rounded-2xl border border-blue-500/10 space-y-6">
                                <h3 className="font-bold text-white flex items-center space-x-2">
                                    <ShieldCheck className="w-5 h-5 text-blue-400" />
                                    <span>School Administrator Credentials</span>
                                </h3>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <input type="email" required placeholder="Admin Email" className="w-full bg-[#0a0c10] border border-white/5 rounded-xl p-3 text-white" onChange={e => setNewSchool({ ...newSchool, adminEmail: e.target.value })} />
                                    <input type="password" required placeholder="Admin Password" className="w-full bg-[#0a0c10] border border-white/5 rounded-xl p-3 text-white" onChange={e => setNewSchool({ ...newSchool, adminPassword: e.target.value })} />
                                    <input type="text" required placeholder="First Name" className="w-full bg-[#0a0c10] border border-white/5 rounded-xl p-3 text-white" onChange={e => setNewSchool({ ...newSchool, adminFirstName: e.target.value })} />
                                    <input type="text" required placeholder="Last Name" className="w-full bg-[#0a0c10] border border-white/5 rounded-xl p-3 text-white" onChange={e => setNewSchool({ ...newSchool, adminLastName: e.target.value })} />
                                </div>
                            </div>

                            {/* Quotas Section */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-slate-400">Max Students</label>
                                    <input type="number" min="1" value={newSchool.maxStudents} className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20" onChange={e => setNewSchool({ ...newSchool, maxStudents: parseInt(e.target.value) || 100 })} />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-slate-400">Max Teachers</label>
                                    <input type="number" min="1" value={newSchool.maxTeachers} className="w-full bg-[#1a1f29] border border-white/5 rounded-2xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20" onChange={e => setNewSchool({ ...newSchool, maxTeachers: parseInt(e.target.value) || 10 })} />
                                </div>
                            </div>

                            <div className="flex justify-end space-x-4 pt-4">
                                <button type="button" onClick={() => setShowAddModal(false)} className="px-6 py-3 rounded-xl hover:bg-white/5 transition-colors font-semibold">Cancel</button>
                                <button type="submit" className="px-8 py-3 bg-blue-600 hover:bg-blue-500 rounded-xl text-white font-bold shadow-lg shadow-blue-600/20 transition-all">Create School</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Delete Confirmation Modal */}
            {deleteConfirm && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
                    <div className="w-full max-w-md bg-[#11141b] rounded-2xl border border-white/10 p-8 shadow-2xl">
                        <h3 className="text-xl font-bold text-white mb-4">Confirm Deletion</h3>
                        <p className="text-slate-400 mb-6">Are you sure you want to delete this school? This action cannot be undone and will remove all associated users.</p>
                        <div className="flex justify-end space-x-4">
                            <button onClick={() => setDeleteConfirm(null)} className="px-5 py-2.5 rounded-xl hover:bg-white/5 transition-colors font-semibold">Cancel</button>
                            <button onClick={() => handleDeleteSchool(deleteConfirm)} className="px-5 py-2.5 bg-red-600 hover:bg-red-500 rounded-xl text-white font-bold transition-all">Delete School</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

function StatCard({ title, value, icon, color }: { title: string, value: string, icon: any, color: "blue" | "emerald" | "amber" | "indigo" }) {
    const colors = {
        blue: "bg-blue-500/10 text-blue-500 border-blue-500/10 shadow-blue-500/5",
        emerald: "bg-emerald-500/10 text-emerald-500 border-emerald-500/10 shadow-emerald-500/5",
        amber: "bg-amber-500/10 text-amber-500 border-amber-500/10 shadow-amber-500/5",
        indigo: "bg-indigo-500/10 text-indigo-500 border-indigo-500/10 shadow-indigo-500/5",
    };

    return (
        <div className={`p-6 rounded-[2rem] border ${colors[color]} backdrop-blur-sm shadow-xl flex flex-col justify-between h-40 group hover:translate-y-[-4px] transition-all duration-300`}>
            <div className="flex items-center justify-between">
                <div className="p-3 rounded-2xl bg-white/5 group-hover:scale-110 transition-transform">{icon}</div>
                <div className="w-1.5 h-1.5 rounded-full bg-slate-700" />
            </div>
            <div>
                <div className="text-3xl font-bold tracking-tight text-white mb-1">{value}</div>
                <div className="text-sm font-semibold text-slate-500 uppercase tracking-widest">{title}</div>
            </div>
        </div>
    );
}
