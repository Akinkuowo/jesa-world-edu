"use client";

import LessonNotebook from "../components/LessonNotebook";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { BookOpen, LogOut, LayoutDashboard, Users, Notebook, FileText, Brain, Award, Calendar } from "lucide-react";

export default function LessonNotebookPage() {
    const router = useRouter();
    const [user, setUser] = useState<any>(null);

    useEffect(() => {
        const savedUser = localStorage.getItem("user");
        if (!savedUser) {
            router.push("/login");
        } else {
            setUser(JSON.parse(savedUser));
        }
    }, [router]);

    if (!user) return null;

    return (
        <div className="min-h-screen bg-[#fafafa]">
            <aside className="fixed left-0 top-0 h-full w-24 bg-white border-r border-slate-200 z-20 flex flex-col items-center py-8 space-y-8 shadow-sm">
                <div className="p-4" onClick={() => router.push("/dashboard/teacher")}>
                    <div className="w-12 h-12 bg-emerald-600 rounded-2xl flex items-center justify-center text-white shadow-lg shadow-emerald-500/20 cursor-pointer">
                        <BookOpen className="w-6 h-6" />
                    </div>
                </div>
                <nav className="flex-1 flex flex-col space-y-4 text-slate-400">
                    <button onClick={() => router.push("/dashboard/teacher")} className="p-4 hover:text-emerald-600 transition-all"><LayoutDashboard /></button>
                    <button className="p-4 bg-emerald-600 text-white rounded-2xl shadow-lg"><Notebook /></button>
                </nav>
            </aside>
            <main className="pl-24">
                <div className="p-10 max-w-7xl mx-auto">
                    <LessonNotebook />
                </div>
            </main>
        </div>
    );
}
