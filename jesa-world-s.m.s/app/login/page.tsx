"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Image from "next/image";
import { School, User, Lock, ArrowRight, Loader2, AlertCircle } from "lucide-react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs));
}

export default function LoginPage() {
    const router = useRouter();
    const [role, setRole] = useState<"ADMIN" | "TEACHER" | "STUDENT" | "PARENT">("STUDENT");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [schoolNumber, setSchoolNumber] = useState("");
    const [studentId, setStudentId] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError("");

        try {
            // If parent is selected, authenticate as student but track parent mode
            const authRole = role === "PARENT" ? "STUDENT" : role;

            // Build request payload based on role
            const payload: any = { password, role: authRole };

            if (role === "STUDENT") {
                payload.studentId = studentId;
            } else if (role === "PARENT") {
                payload.email = email;
            } else if (role === "TEACHER") {
                payload.email = email;
            } else if (role === "ADMIN") {
                payload.email = email;
                payload.schoolNumber = schoolNumber;
            }

            const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Login failed");
            }

            localStorage.setItem("token", data.token);
            localStorage.setItem("user", JSON.stringify(data.user));

            // Store parent mode flag if parent login
            if (role === "PARENT") {
                localStorage.setItem("isParentMode", "true");
            }

            // Redirect based on role
            const rolePath = role.toLowerCase();
            router.push(`/dashboard/${rolePath}`);
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="relative min-h-screen flex items-center justify-center bg-slate-900 selection:bg-blue-500/30">
            {/* Background Image with Overlay */}
            <div className="absolute inset-0 z-0">
                <Image
                    src="/school_background.png"
                    alt="School Background"
                    fill
                    className="object-cover opacity-30 grayscale-[0.2]"
                    priority
                />
                <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-slate-900/90 to-blue-900/50" />
            </div>

            <div className="relative z-10 w-full max-w-[1100px] grid lg:grid-cols-2 gap-8 p-4 lg:p-8">

                {/* Left Side: Branding */}
                <div className="hidden lg:flex flex-col justify-center text-white space-y-8 pr-8">
                    <div className="inline-flex items-center space-x-3 group">
                        <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/20 group-hover:scale-110 transition-transform duration-300">
                            <School className="w-7 h-7" />
                        </div>
                        <span className="text-3xl font-bold tracking-tight">Jesa World <span className="text-blue-500">SMS</span></span>
                    </div>

                    <div className="space-y-4">
                        <h1 className="text-5xl font-extrabold leading-tight tracking-tighter">
                            Manage your school <br />
                            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-indigo-400">
                                with intelligence.
                            </span>
                        </h1>
                        <p className="text-lg text-slate-400 max-w-md">
                            A unified platform for administrators, teachers, and students to collaborate and excel in the digital age.
                        </p>
                    </div>

                    <div className="grid grid-cols-2 gap-6 pt-4">
                        <div className="p-4 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-sm">
                            <div className="text-blue-400 font-bold text-2xl mb-1">99.9%</div>
                            <div className="text-slate-500 text-sm">System Uptime</div>
                        </div>
                        <div className="p-4 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-sm">
                            <div className="text-blue-400 font-bold text-2xl mb-1">Secure</div>
                            <div className="text-slate-500 text-sm">Encrypted Data</div>
                        </div>
                    </div>
                </div>

                {/* Right Side: Login Card */}
                <div className="w-full flex items-center">
                    <div className="w-full bg-slate-800/50 backdrop-blur-xl rounded-[2.5rem] border border-white/10 p-8 lg:p-12 shadow-2xl overflow-hidden relative">
                        {/* Animated Glow */}
                        <div className="absolute -top-24 -right-24 w-48 h-48 bg-blue-500/20 blur-[80px] rounded-full" />
                        <div className="absolute -bottom-24 -left-24 w-48 h-48 bg-indigo-500/20 blur-[80px] rounded-full" />

                        <div className="mb-10">
                            <h2 className="text-3xl font-bold text-white mb-2">Welcome Back</h2>
                            <p className="text-slate-400">Select your role and sign in to continue</p>
                        </div>

                        {/* Role Switcher */}
                        <div className="grid grid-cols-2 gap-2 p-1.5 bg-slate-900/50 rounded-2xl mb-8 border border-white/5">
                            {(["STUDENT", "PARENT", "TEACHER", "ADMIN"] as const).map((r) => (
                                <button
                                    key={r}
                                    onClick={() => {
                                        setRole(r);
                                        setError("");
                                    }}
                                    className={cn(
                                        "py-2.5 px-4 rounded-xl text-sm font-medium transition-all duration-200",
                                        role === r
                                            ? "bg-blue-600 text-white shadow-lg shadow-blue-500/20"
                                            : "text-slate-400 hover:text-white hover:bg-white/5"
                                    )}
                                >
                                    {r.charAt(0) + r.slice(1).toLowerCase()}
                                </button>
                            ))}
                        </div>

                        <form onSubmit={handleLogin} className="space-y-5">
                            {error && (
                                <div className="p-4 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center space-x-3 text-red-400 text-sm animate-in fade-in slide-in-from-top-2">
                                    <AlertCircle className="w-5 h-5 flex-shrink-0" />
                                    <span>{error}</span>
                                </div>
                            )}

                            {/* Admin: School Number + Email */}
                            {role === "ADMIN" && (
                                <>
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-slate-300 ml-1">School Number</label>
                                        <div className="relative group">
                                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500 group-focus-within:text-blue-500 transition-colors">
                                                <School className="w-5 h-5" />
                                            </div>
                                            <input
                                                type="text"
                                                required
                                                placeholder="Enter unique school number"
                                                value={schoolNumber}
                                                onChange={(e) => setSchoolNumber(e.target.value)}
                                                className="w-full bg-slate-900/50 border border-white/10 rounded-2xl py-4 pl-12 pr-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/40 transition-all"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-2">
                                        <label className="text-sm font-medium text-slate-300 ml-1">Email Address</label>
                                        <div className="relative group">
                                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500 group-focus-within:text-blue-500 transition-colors">
                                                <User className="w-5 h-5" />
                                            </div>
                                            <input
                                                type="email"
                                                required
                                                placeholder="name@example.com"
                                                value={email}
                                                onChange={(e) => setEmail(e.target.value)}
                                                className="w-full bg-slate-900/50 border border-white/10 rounded-2xl py-4 pl-12 pr-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/40 transition-all"
                                            />
                                        </div>
                                    </div>
                                </>
                            )}

                            {/* Teacher: Email Only */}
                            {role === "TEACHER" && (
                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-slate-300 ml-1">Email Address</label>
                                    <div className="relative group">
                                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500 group-focus-within:text-blue-500 transition-colors">
                                            <User className="w-5 h-5" />
                                        </div>
                                        <input
                                            type="email"
                                            required
                                            placeholder="name@example.com"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                            className="w-full bg-slate-900/50 border border-white/10 rounded-2xl py-4 pl-12 pr-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/40 transition-all"
                                        />
                                    </div>
                                </div>
                            )}

                            {/* Student: Student ID Only */}
                            {role === "STUDENT" && (
                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-slate-300 ml-1">Student ID</label>
                                    <div className="relative group">
                                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500 group-focus-within:text-blue-500 transition-colors">
                                            <User className="w-5 h-5" />
                                        </div>
                                        <input
                                            type="text"
                                            required
                                            placeholder="STU-XXXXXX-XXX"
                                            value={studentId}
                                            onChange={(e) => setStudentId(e.target.value)}
                                            className="w-full bg-slate-900/50 border border-white/10 rounded-2xl py-4 pl-12 pr-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/40 transition-all"
                                        />
                                    </div>
                                </div>
                            )}

                            {/* Parent: Student Email */}
                            {role === "PARENT" && (
                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-slate-300 ml-1">Student Email</label>
                                    <div className="relative group">
                                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500 group-focus-within:text-blue-500 transition-colors">
                                            <User className="w-5 h-5" />
                                        </div>
                                        <input
                                            type="email"
                                            required
                                            placeholder="child@school.com"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                            className="w-full bg-slate-900/50 border border-white/10 rounded-2xl py-4 pl-12 pr-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/40 transition-all"
                                        />
                                    </div>
                                </div>
                            )}

                            <div className="space-y-2">
                                <div className="flex justify-between items-center ml-1">
                                    <label className="text-sm font-medium text-slate-300">Password</label>
                                    <button type="button" className="text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors">
                                        Forgot Password?
                                    </button>
                                </div>
                                <div className="relative group">
                                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500 group-focus-within:text-blue-500 transition-colors">
                                        <Lock className="w-5 h-5" />
                                    </div>
                                    <input
                                        type="password"
                                        required
                                        placeholder="••••••••"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        className="w-full bg-slate-900/50 border border-white/10 rounded-2xl py-4 pl-12 pr-4 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/40 transition-all"
                                    />
                                </div>
                            </div>

                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-4 rounded-2xl shadow-xl shadow-blue-600/20 flex items-center justify-center space-x-2 transition-all active:scale-[0.98] disabled:opacity-70 disabled:active:scale-100 group mt-4"
                            >
                                {loading ? (
                                    <Loader2 className="w-6 h-6 animate-spin" />
                                ) : (
                                    <>
                                        <span>Sign In</span>
                                        <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                                    </>
                                )}
                            </button>
                        </form>

                        <p className="text-center text-slate-500 text-sm mt-8">
                            Don&apos;t have an account?{" "}
                            <button className="text-white font-semibold hover:text-blue-400 transition-colors">
                                Contact your school admin
                            </button>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
