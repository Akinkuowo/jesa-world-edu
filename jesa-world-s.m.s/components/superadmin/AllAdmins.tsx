"use client";

import { useState } from "react";
import { Search, Users, Mail, Phone, MapPin, Loader2, ShieldCheck, School } from "lucide-react";

interface AllAdminsProps {
    admins: any[];
    loading: boolean;
}

export default function AllAdmins({ admins, loading }: AllAdminsProps) {
    const [searchQuery, setSearchQuery] = useState("");

    const filteredAdmins = admins.filter(admin =>
        admin.firstName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        admin.lastName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        admin.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
        admin.school?.name.toLowerCase().includes(searchQuery.toLowerCase())
    );

    return (
        <div className="bg-[#11141b] rounded-3xl border border-white/5 overflow-hidden shadow-2xl">
            <div className="p-8 border-b border-white/5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <h2 className="text-xl font-bold text-white">System Administrators</h2>
                <div className="relative">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                        type="text"
                        placeholder="Search administrators or schools..."
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
                            <th className="px-8 py-5">Administrator</th>
                            <th className="px-8 py-5">Assigned Institution</th>
                            <th className="px-8 py-5">Contact Info</th>
                            <th className="px-8 py-5">Status</th>
                            <th className="px-8 py-5 text-right">Added On</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                        {loading ? (
                            <tr>
                                <td colSpan={5} className="px-8 py-20 text-center">
                                    <div className="flex flex-col items-center space-y-4">
                                        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
                                        <span className="text-slate-500 font-medium">Fetching administrators...</span>
                                    </div>
                                </td>
                            </tr>
                        ) : filteredAdmins.length === 0 ? (
                            <tr>
                                <td colSpan={5} className="px-8 py-20 text-center text-slate-500 italic">
                                    {searchQuery ? "No matching administrators found." : "No administrators registered yet."}
                                </td>
                            </tr>
                        ) : filteredAdmins.map((admin) => (
                            <tr key={admin.id} className="hover:bg-white/2 transition-colors group">
                                <td className="px-8 py-6">
                                    <div className="flex items-center space-x-4">
                                        <div className="w-10 h-10 rounded-full bg-blue-600/10 flex items-center justify-center text-blue-400 font-bold border border-blue-500/10">
                                            {admin.firstName.charAt(0)}{admin.lastName.charAt(0)}
                                        </div>
                                        <div>
                                            <div className="text-white font-bold">{admin.firstName} {admin.lastName}</div>
                                            <div className="flex items-center space-x-1.5 text-xs text-slate-500">
                                                <ShieldCheck className="w-3 h-3 text-blue-500" />
                                                <span>Admin</span>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                                <td className="px-8 py-6">
                                    {admin.school ? (
                                        <div className="flex items-center space-x-3">
                                            <div className="p-2 rounded-lg bg-indigo-500/10">
                                                <School className="w-4 h-4 text-indigo-400" />
                                            </div>
                                            <div>
                                                <div className="text-sm font-semibold text-white">{admin.school.name}</div>
                                                <div className="text-[10px] font-mono text-slate-500">{admin.school.schoolNumber}</div>
                                            </div>
                                        </div>
                                    ) : (
                                        <span className="text-slate-600 italic text-sm">No School Assigned</span>
                                    )}
                                </td>
                                <td className="px-8 py-6">
                                    <div className="space-y-1">
                                        <div className="flex items-center space-x-2 text-xs text-slate-400">
                                            <Mail className="w-3 h-3" />
                                            <span>{admin.email}</span>
                                        </div>
                                        <div className="flex items-center space-x-2 text-xs text-slate-500">
                                            <Phone className="w-3 h-3" />
                                            <span>{admin.phone || 'N/A'}</span>
                                        </div>
                                    </div>
                                </td>
                                <td className="px-8 py-6">
                                    <span className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full text-[10px] font-black tracking-widest uppercase border ${admin.isActive
                                            ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/10'
                                            : 'bg-red-500/10 text-red-500 border-red-500/10'
                                        }`}>
                                        <div className={`w-1 h-1 rounded-full ${admin.isActive ? 'bg-emerald-500' : 'bg-red-500'}`} />
                                        <span>{admin.isActive ? 'Active' : 'Inactive'}</span>
                                    </span>
                                </td>
                                <td className="px-8 py-6 text-right">
                                    <div className="text-sm text-slate-500 font-medium">
                                        {new Date(admin.createdAt).toLocaleDateString()}
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
