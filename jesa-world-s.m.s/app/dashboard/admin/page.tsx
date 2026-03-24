"use client";

import { useEffect, useState } from "react";
import {
    Users,
    GraduationCap,
    BookOpen,
    Settings,
    LogOut,
    LayoutDashboard,
    UserPlus,
    ArrowUpRight,
    Edit,
    Trash2,
    ArrowUpCircle,
    FileText,
    Upload,
    ClipboardCheck,
    Trophy,
    Search,
    Menu,
    X
} from "lucide-react";
import { useRouter } from "next/navigation";
import Papa from "papaparse";
import Attendance from "./components/Attendance";
import Exams from "./components/Exams";
import SettingsView from "./components/Settings";

export default function AdminDashboard() {
    const router = useRouter();
    const [user, setUser] = useState<any>(null);
    const [stats, setStats] = useState({ teacherCount: 0, studentCount: 0 });
    const [showAddModal, setShowAddModal] = useState(false);
    const [showBulkModal, setShowBulkModal] = useState(false);
    const [feedback, setFeedback] = useState<{ type: 'success' | 'error', message: string } | null>(null);
    const [activeView, setActiveView] = useState<'DASHBOARD' | 'TEACHERS' | 'STUDENTS' | 'CURRICULUM' | 'ATTENDANCE' | 'EXAMS' | 'SETTINGS'>('DASHBOARD');
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);
    const [roleUsers, setRoleUsers] = useState<any[]>([]);
    const [loadingUsers, setLoadingUsers] = useState(false);
    const [showEditModal, setShowEditModal] = useState(false);
    const [editingUser, setEditingUser] = useState<any>(null);
    const [studentSearch, setStudentSearch] = useState("");
    const [classFilter, setClassFilter] = useState("");
    const [showAddSubjectModal, setShowAddSubjectModal] = useState(false);
    const [searchSubject, setSearchSubject] = useState("");
    const [newSubject, setNewSubject] = useState({ name: "", section: "JUNIOR", category: "" });
    const [showPromoteModal, setShowPromoteModal] = useState(false);
    const [promotingStudent, setPromotingStudent] = useState<any>(null);
    const [newClassForPromotion, setNewClassForPromotion] = useState("");
    const [newEmployee, setNewEmployee] = useState({
        email: "",
        password: "",
        firstName: "",
        lastName: "",
        role: "TEACHER",
        phone: "",
        address: "",
        studentClass: "",
        subjects: [] as string[]
    });
    const [bulkFile, setBulkFile] = useState<File | null>(null);
    const [bulkLoading, setBulkLoading] = useState(false);
    const [availableSubjects, setAvailableSubjects] = useState<any[]>([]);
    const [enrollmentTrend, setEnrollmentTrend] = useState<{ month: string; count: number }[]>([]);
    const [loadingEnrollment, setLoadingEnrollment] = useState(false);
    const [selectedStudents, setSelectedStudents] = useState<string[]>([]);
    const [showBulkPromoteModal, setShowBulkPromoteModal] = useState(false);
    const [bulkPromoteClass, setBulkPromoteClass] = useState("");

    useEffect(() => {
        const fetchSubjects = async () => {
            try {
                const token = localStorage.getItem("token");
                const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/subjects`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                if (res.ok) {
                    const data = await res.json();
                    setAvailableSubjects(data);
                }
            } catch (err) {
                console.error("Failed to fetch subjects", err);
            }
        };
        fetchSubjects();
    }, []);

    useEffect(() => {
        const savedUser = localStorage.getItem("user");
        if (!savedUser) {
            router.push("/login");
        } else {
            setUser(JSON.parse(savedUser));
            fetchStats();
        }
    }, [router]);

    useEffect(() => {
        setStudentSearch("");
        setClassFilter("");
        setSelectedStudents([]);
        if (activeView === 'TEACHERS') {
            fetchUsers('TEACHER');
        } else if (activeView === 'STUDENTS') {
            fetchUsers('STUDENT');
        } else if (activeView === 'DASHBOARD') {
            fetchStats();
            fetchEnrollmentTrend();
        }
    }, [activeView]);

    const fetchStats = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/stats`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setStats(data);
            }
        } catch (err) {
            console.error("Failed to fetch stats", err);
        }
    };

    const fetchEnrollmentTrend = async () => {
        setLoadingEnrollment(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/enrollment-trend`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setEnrollmentTrend(data.enrollmentData);
            }
        } catch (err) {
            console.error("Failed to fetch enrollment trend", err);
        } finally {
            setLoadingEnrollment(false);
        }
    };

    const fetchUsers = async (role: string) => {
        setLoadingUsers(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users/${role}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setRoleUsers(data);
            }
        } catch (err) {
            console.error(`Failed to fetch ${role}s`, err);
        } finally {
            setLoadingUsers(false);
        }
    };

    const handleUpdateUser = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!editingUser) return;

        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users/${editingUser.id}`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(editingUser)
            });

            if (res.ok) {
                setShowEditModal(false);
                setEditingUser(null);
                setFeedback({ type: 'success', message: 'User updated successfully!' });
                if (activeView === 'TEACHERS') fetchUsers('TEACHER');
                if (activeView === 'STUDENTS') fetchUsers('STUDENT');
                setTimeout(() => setFeedback(null), 3000);
            } else {
                const data = await res.json();
                setFeedback({ type: 'error', message: data.error || 'Failed to update user' });
            }
        } catch (err) {
            setFeedback({ type: 'error', message: 'Network error. Please try again.' });
        }
    };

    const handleAddEmployee = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(newEmployee)
            });
            if (res.ok) {
                setShowAddModal(false);
                setFeedback({ type: 'success', message: `${newEmployee.role === 'TEACHER' ? 'Teacher' : 'Student'} added successfully!` });
                fetchStats();
                if (activeView === 'TEACHERS' && newEmployee.role === 'TEACHER') fetchUsers('TEACHER');
                if (activeView === 'STUDENTS' && newEmployee.role === 'STUDENT') fetchUsers('STUDENT');
                setNewEmployee({ email: "", password: "", firstName: "", lastName: "", role: "TEACHER", phone: "", address: "", studentClass: "", subjects: [] });
                setTimeout(() => setFeedback(null), 3000);
            } else {
                const data = await res.json();
                setFeedback({ type: 'error', message: data.error || 'Failed to add employee' });
            }
        } catch (err) {
            setFeedback({ type: 'error', message: 'Network error. Please try again.' });
        }
    };

    const handleBulkUpload = () => {
        if (!bulkFile) return;
        setBulkLoading(true);

        Papa.parse(bulkFile, {
            header: true,
            skipEmptyLines: true,
            complete: async (results) => {
                const students = results.data.map((row: any) => ({
                    firstName: row.firstName || row['First Name'],
                    lastName: row.lastName || row['Last Name'],
                    email: row.email || row['Email'],
                    password: row.password || row['Password'] || '123456', // Default password if missing, or require it
                    studentClass: row.studentClass || row['Class'],
                    phone: row.phone || row['Phone'],
                    address: row.address || row['Address'],
                    gender: row.gender || row['Gender']
                }));

                try {
                    const token = localStorage.getItem("token");
                    const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users/bulk`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            Authorization: `Bearer ${token}`
                        },
                        body: JSON.stringify({ students })
                    });

                    const data = await res.json();

                    if (res.ok) {
                        setFeedback({ type: 'success', message: `Processed: ${data.successCount} success, ${data.failureCount} failed.` });
                        setShowBulkModal(false);
                        setBulkFile(null);
                        fetchUsers('STUDENT');
                    } else {
                        setFeedback({ type: 'error', message: data.error || 'Bulk upload failed' });
                    }
                } catch (err) {
                    setFeedback({ type: 'error', message: 'Network error during bulk upload.' });
                } finally {
                    setBulkLoading(false);
                    setTimeout(() => setFeedback(null), 5000);
                }
            },
            error: (err) => {
                setFeedback({ type: 'error', message: `CSV Parsing Error: ${err.message}` });
                setBulkLoading(false);
            }
        });
    };

    const handleGraduateStudent = async (student: any) => {
        if (!confirm(`Are you sure you want to graduate ${student.firstName} ${student.lastName}? This will move them to the Graduated group.`)) return;

        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users/${student.id}`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    ...student,
                    studentClass: "GRADUATED",
                    isActive: false // Usually graduated students are inactive for current records
                })
            });

            if (res.ok) {
                setFeedback({ type: 'success', message: `${student.firstName} has been graduated successfully!` });
                fetchUsers('STUDENT');
                setTimeout(() => setFeedback(null), 3000);
            } else {
                const data = await res.json();
                setFeedback({ type: 'error', message: data.error || 'Failed to graduate student' });
            }
        } catch (err) {
            setFeedback({ type: 'error', message: 'Network error. Please try again.' });
        }
    };

    const handleBulkPromote = async () => {
        if (selectedStudents.length === 0) {
            setFeedback({ type: 'error', message: 'Please select at least one student' });
            return;
        }

        if (!bulkPromoteClass) {
            setFeedback({ type: 'error', message: 'Please select a class' });
            return;
        }

        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users/bulk-promote`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    studentIds: selectedStudents,
                    newClass: bulkPromoteClass
                })
            });

            if (res.ok) {
                const data = await res.json();
                setFeedback({ type: 'success', message: data.message });
                setShowBulkPromoteModal(false);
                setSelectedStudents([]);
                setBulkPromoteClass("");
                fetchUsers('STUDENT');
                setTimeout(() => setFeedback(null), 3000);
            } else {
                const data = await res.json();
                setFeedback({ type: 'error', message: data.error || 'Failed to promote students' });
            }
        } catch (err) {
            setFeedback({ type: 'error', message: 'Network error. Please try again.' });
        }
    };

    const handleLogout = () => {
        localStorage.clear();
        router.push("/login");
    };

    if (!user) return null;

    return (
        <div className="min-h-screen bg-[#f8fafc] text-slate-800 font-sans">
            {/* Mobile Overlay */}
            {isSidebarOpen && (
                <div 
                    className="fixed inset-0 bg-black/50 z-30 lg:hidden backdrop-blur-sm transition-opacity"
                    onClick={() => setIsSidebarOpen(false)}
                />
            )}

            {/* Sidebar */}
            <aside className={`fixed left-0 top-0 h-full w-72 bg-white border-r border-slate-200 z-40 flex flex-col shadow-sm transition-transform duration-300 lg:translate-x-0 ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
                <div className="p-8">
                    <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center shadow-lg shadow-indigo-500/20">
                            <GraduationCap className="w-6 h-6 text-white" />
                        </div>
                        <span className="text-xl font-bold text-slate-900">{user.schoolName}</span>
                    </div>
                </div>

                <nav className="flex-1 px-6 space-y-1">
                    <div className="text-[10px] font-bold text-slate-400 uppercase tracking-[0.2em] mb-4 px-4 pt-4">Workspace</div>
                    <NavItem active={activeView === 'DASHBOARD'} icon={<LayoutDashboard />} label="Dashboard" onClick={() => { setActiveView('DASHBOARD'); setIsSidebarOpen(false); }} />
                    <NavItem active={activeView === 'TEACHERS'} icon={<Users />} label="Teachers" onClick={() => { setActiveView('TEACHERS'); setIsSidebarOpen(false); }} />
                    <NavItem active={activeView === 'STUDENTS'} icon={<GraduationCap />} label="Students" onClick={() => { setActiveView('STUDENTS'); setIsSidebarOpen(false); }} />
                    <NavItem active={activeView === 'CURRICULUM'} icon={<BookOpen />} label="Curriculum" onClick={() => { setActiveView('CURRICULUM'); setIsSidebarOpen(false); }} />
                    <NavItem active={activeView === 'ATTENDANCE'} icon={<ClipboardCheck />} label="Attendance" onClick={() => { setActiveView('ATTENDANCE'); setIsSidebarOpen(false); }} />
                    <NavItem active={activeView === 'EXAMS'} icon={<FileText />} label="Exams" onClick={() => { setActiveView('EXAMS'); setIsSidebarOpen(false); }} />

                    <div className="text-[10px] font-bold text-slate-400 uppercase tracking-[0.2em] mb-4 px-4 pt-8">Account</div>
                    <NavItem active={activeView === 'SETTINGS'} icon={<Settings />} label="Settings" onClick={() => { setActiveView('SETTINGS'); setIsSidebarOpen(false); }} />
                    <button onClick={handleLogout} className="w-full flex items-center space-x-3 px-4 py-3 text-slate-500 hover:text-red-600 hover:bg-red-50 transition-all rounded-xl">
                        <LogOut className="w-5 h-5" />
                        <span className="font-semibold text-sm">Sign Out</span>
                    </button>
                </nav>

                <div className="p-6 hidden lg:block">
                    <div className="bg-indigo-600 rounded-2xl p-6 text-white shadow-xl shadow-indigo-600/20 relative overflow-hidden group">
                        <div className="absolute -right-4 -top-4 w-24 h-24 bg-white/10 rounded-full group-hover:scale-150 transition-transform duration-500" />
                        <h4 className="font-bold relative z-10 mb-1">Need help?</h4>
                        <p className="text-xs text-indigo-100 relative z-10 mb-4 opacity-80">Our support team is available 24/7 for you.</p>
                        <button className="bg-white text-indigo-600 py-2 px-4 rounded-lg text-xs font-bold relative z-10 hover:bg-slate-50 transition-colors">Support Center</button>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="lg:ml-72 p-6 lg:p-10 max-w-[1600px] mx-auto min-h-screen">
                <header className="flex flex-col md:flex-row md:items-center justify-between mb-8 lg:mb-12 gap-6">
                    <div className="flex items-center gap-4">
                        <button 
                            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
                            className="lg:hidden p-2 hover:bg-slate-100 rounded-xl transition-colors text-slate-600"
                        >
                            {isSidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
                        </button>
                        <div>
                            <h1 className="text-2xl lg:text-3xl font-black text-slate-900 tracking-tight">
                                {activeView === 'DASHBOARD' ? 'Admin Dashboard' :
                                    activeView === 'TEACHERS' ? 'Teachers Management' :
                                        activeView === 'STUDENTS' ? 'Students Management' :
                                            activeView === 'CURRICULUM' ? 'Academic Curriculum' :
                                                activeView === 'ATTENDANCE' ? 'Student Attendance' :
                                                    activeView === 'EXAMS' ? 'Exams Management' :
                                                        'School Settings'}
                            </h1>
                            <p className="text-sm lg:text-base text-slate-500 font-medium">Welcome back, <span className="text-indigo-600">{user.firstName}</span>.</p>
                        </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-3">
                        {activeView === 'STUDENTS' && (
                            <>
                                <button onClick={() => setShowBulkModal(true)} className="flex items-center space-x-2 bg-emerald-600 py-2.5 px-4 lg:px-6 rounded-xl text-xs lg:text-sm font-bold text-white shadow-lg shadow-emerald-600/20 hover:bg-emerald-700 transition-all">
                                    <Upload className="w-4 h-4" />
                                    <span>Bulk Upload</span>
                                </button>
                                {selectedStudents.length > 0 && (
                                    <button onClick={() => setShowBulkPromoteModal(true)} className="flex items-center space-x-2 bg-purple-600 py-2.5 px-4 lg:px-6 rounded-xl text-xs lg:text-sm font-bold text-white shadow-lg shadow-purple-600/20 hover:bg-purple-700 transition-all">
                                        <ArrowUpCircle className="w-4 h-4" />
                                        <span>Promote ({selectedStudents.length})</span>
                                    </button>
                                )}
                            </>
                        )}
                        <button onClick={() => activeView === 'CURRICULUM' ? setShowAddSubjectModal(true) : setShowAddModal(true)} className="flex items-center space-x-2 bg-indigo-600 py-2.5 px-4 lg:px-6 rounded-xl text-xs lg:text-sm font-bold text-white shadow-lg shadow-indigo-600/20 hover:bg-indigo-700 transition-all">
                            {activeView === 'CURRICULUM' ? <BookOpen className="w-4 h-4" /> : <UserPlus className="w-4 h-4" />}
                            <span>Add {activeView === 'STUDENTS' ? 'Student' : activeView === 'TEACHERS' ? 'Teacher' : activeView === 'CURRICULUM' ? 'Subject' : 'Employee'}</span>
                        </button>
                    </div>
                </header>

                {/* Feedback Toast */}
                {feedback && (
                    <div className={`mb-6 p-4 rounded-xl flex items-center space-x-3 ${feedback.type === 'success' ? 'bg-emerald-100 text-emerald-700 border border-emerald-200' : 'bg-red-100 text-red-700 border border-red-200'
                        }`}>
                        <span className="font-medium">{feedback.message}</span>
                    </div>
                )}

                {activeView === 'DASHBOARD' ? (
                    <>
                        {/* Stats Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
                            <AdminStatCard title="Total Students" value={stats.studentCount.toString()} trend="+12" icon={<GraduationCap className="text-blue-600" />} color="blue" />
                            <AdminStatCard title="Total Teachers" value={stats.teacherCount.toString()} trend="+3" icon={<Users className="text-purple-600" />} color="purple" />
                            <AdminStatCard title="Total Subjects" value="12" trend="0" icon={<BookOpen className="text-emerald-600" />} color="emerald" />
                        </div>

                        {/* Recent Activity Mockup */}
                        <div className="grid lg:grid-cols-3 gap-8">
                            <div className="lg:col-span-2 bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm">
                                <div className="flex items-center justify-between mb-8">
                                    <h2 className="text-xl font-black text-slate-900">Student Enrollment Trend</h2>
                                    <select className="bg-slate-50 border border-slate-200 rounded-lg py-1 px-3 text-sm font-semibold outline-none">
                                        <option>Last 12 Months</option>
                                    </select>
                                </div>
                                {loadingEnrollment ? (
                                    <div className="h-64 flex items-center justify-center text-slate-400 font-medium">
                                        Loading enrollment data...
                                    </div>
                                ) : (
                                    <>
                                        <div className="h-64 flex items-end justify-between space-x-2 px-2">
                                            {enrollmentTrend.map((data, i) => {
                                                const maxCount = Math.max(...enrollmentTrend.map(d => d.count), 1);
                                                const heightPercent = (data.count / maxCount) * 100;
                                                return (
                                                    <div key={i} className="w-full bg-indigo-50 rounded-t-lg relative group transition-all">
                                                        <div className="absolute bottom-0 w-full bg-indigo-600 rounded-t-lg transition-all duration-700" style={{ height: `${heightPercent}%` }}>
                                                            <div className="absolute -top-10 left-1/2 -translate-x-1/2 bg-slate-900 text-white text-[10px] py-1 px-2 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                                                                {data.count} {data.count === 1 ? 'student' : 'students'}
                                                            </div>
                                                        </div>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                        <div className="flex justify-between mt-4 px-2">
                                            {enrollmentTrend.map((data, i) => (
                                                <span key={i} className="text-[10px] font-bold text-slate-400">{data.month}</span>
                                            ))}
                                        </div>
                                    </>
                                )}
                            </div>

                            <div className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm">
                                <h2 className="text-xl font-black text-slate-900 mb-6">Quick Actions</h2>
                                <div className="space-y-3">
                                    <QuickActionItem icon={<ClipboardCheck className="text-blue-500" />} label="Process Salaries" />
                                    <QuickActionItem icon={<Users className="text-purple-500" />} label="Parent-Teacher Meetings" />
                                    <QuickActionItem icon={<ArrowUpRight className="text-emerald-500" />} label="Generate Yearly Report" />
                                </div>
                                <div className="mt-8 pt-8 border-t border-slate-100">
                                    <h3 className="text-sm font-bold text-slate-900 mb-4">Storage Usage</h3>
                                    <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                                        <div className="h-full bg-indigo-600 w-[64%]" />
                                    </div>
                                    <div className="flex justify-between mt-2 text-[10px] font-bold text-slate-400">
                                        <span>6.4 GB OF 10 GB USED</span>
                                        <span>64%</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </>
                ) : activeView === 'CURRICULUM' ? (
                    <div className="space-y-8">
                        <div className="bg-white rounded-[2rem] border border-slate-200 p-8 shadow-sm">
                            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
                                <div>
                                    <h2 className="text-xl font-black text-slate-900">Curriculum List</h2>
                                    <p className="text-sm text-slate-500 font-medium">Manage available subjects for your school.</p>
                                </div>
                                <div className="flex items-center space-x-3">
                                    <div className="relative">
                                        <input
                                            type="text"
                                            placeholder="Search subjects..."
                                            value={searchSubject}
                                            onChange={e => setSearchSubject(e.target.value)}
                                            className="bg-slate-50 border border-slate-200 rounded-xl py-2 pl-10 pr-4 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20 w-64"
                                        />
                                        <BookOpen className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                                    </div>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                                {['JUNIOR', 'SENIOR'].map(section => (
                                    <div key={section} className="space-y-4">
                                        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                                            <h3 className="text-sm font-black text-indigo-600 uppercase tracking-widest">{section} SECONDARY</h3>
                                            <span className="text-[10px] bg-indigo-50 text-indigo-700 px-2 py-0.5 rounded-full font-bold">
                                                {availableSubjects.filter(s => s.section === section).length} Total
                                            </span>
                                        </div>
                                        <div className="bg-slate-50/50 rounded-2xl p-4 max-h-[500px] overflow-y-auto custom-scrollbar border border-slate-100">
                                            <div className="grid grid-cols-1 gap-2">
                                                {availableSubjects
                                                    .filter(s => s.section === section && s.name.toLowerCase().includes(searchSubject.toLowerCase()))
                                                    .map(subject => (
                                                        <div key={subject.id} className="bg-white p-3 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between group hover:border-indigo-200 transition-all">
                                                            <div className="flex items-center space-x-3">
                                                                <div className="w-8 h-8 bg-indigo-50 text-indigo-600 rounded-lg flex items-center justify-center font-bold text-xs uppercase">
                                                                    {subject.name.substring(0, 2)}
                                                                </div>
                                                                <div>
                                                                    <div className="text-sm font-bold text-slate-900">{subject.name}</div>
                                                                    {subject.category && (
                                                                        <div className="text-[10px] text-slate-400 font-bold uppercase">{subject.category}</div>
                                                                    )}
                                                                </div>
                                                            </div>
                                                            <button
                                                                onClick={async () => {
                                                                    if (confirm(`Are you sure you want to remove ${subject.name}?`)) {
                                                                        try {
                                                                            const token = localStorage.getItem("token");
                                                                            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/subjects/${subject.id}`, {
                                                                                method: "DELETE",
                                                                                headers: { Authorization: `Bearer ${token}` }
                                                                            });
                                                                            if (res.ok) {
                                                                                setAvailableSubjects(availableSubjects.filter(s => s.id !== subject.id));
                                                                            }
                                                                        } catch (err) {
                                                                            console.error(err);
                                                                        }
                                                                    }
                                                                }}
                                                                className="opacity-0 group-hover:opacity-100 p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-all"
                                                            >
                                                                <Trash2 className="w-4 h-4" />
                                                            </button>
                                                        </div>
                                                    ))}
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                ) : activeView === 'ATTENDANCE' ? (
                    <Attendance />
                ) : activeView === 'EXAMS' ? (
                    <Exams />
                ) : activeView === 'SETTINGS' ? (
                    <SettingsView />
                ) : (
                    <div className="space-y-6">
                        {/* Filter Bar for Teachers/Students */}
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-white p-6 rounded-[1.5rem] border border-slate-200 shadow-sm">
                            <div className="flex flex-1 items-center space-x-4">
                                <div className="relative flex-1 max-w-md">
                                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                                    <input
                                        type="text"
                                        placeholder={`Search ${activeView.toLowerCase()}...`}
                                        value={studentSearch}
                                        onChange={(e) => setStudentSearch(e.target.value)}
                                        className="w-full pl-10 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-sm font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    />
                                </div>
                                {activeView === 'STUDENTS' && (
                                    <select
                                        value={classFilter}
                                        onChange={(e) => setClassFilter(e.target.value)}
                                        className="bg-slate-50 border border-slate-200 rounded-xl px-4 py-2 text-sm font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    >
                                        <option value="">All Classes</option>
                                        <option value="js1">JS1</option>
                                        <option value="js2">JS2</option>
                                        <option value="js3">JS3</option>
                                        <option value="ss1">SS1</option>
                                        <option value="ss2">SS2</option>
                                        <option value="ss3">SS3</option>
                                        <option value="GRADUATED">GRADUATED</option>
                                    </select>
                                )}
                            </div>
                            <div className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                                {roleUsers.filter(u => {
                                    const matchesSearch = (u.firstName + " " + u.lastName + " " + u.email).toLowerCase().includes(studentSearch.toLowerCase());
                                    const matchesClass = !classFilter || u.studentClass?.toLowerCase() === classFilter.toLowerCase();
                                    return matchesSearch && matchesClass;
                                }).length} Results Found
                            </div>
                        </div>

                        <div className="bg-white rounded-[2rem] border border-slate-200 overflow-x-auto shadow-sm custom-scrollbar">
                            <div className="min-w-[1000px]">
                            {loadingUsers ? (
                                <div className="p-20 text-center text-slate-400 font-bold">Loading {activeView.toLowerCase()}...</div>
                            ) : (
                                <table className="w-full text-left relative">
                                    <thead className="bg-slate-50 border-b border-slate-100 sticky top-0 z-10 shadow-sm">
                                        <tr>
                                            {activeView === 'STUDENTS' && (
                                                <th className="px-4 py-5">
                                                    <input
                                                        type="checkbox"
                                                        checked={selectedStudents.length === roleUsers.filter(u => {
                                                            const matchesSearch = (u.firstName + " " + u.lastName + " " + u.email).toLowerCase().includes(studentSearch.toLowerCase());
                                                            const matchesClass = !classFilter || u.studentClass?.toLowerCase() === classFilter.toLowerCase();
                                                            return matchesSearch && matchesClass;
                                                        }).length && roleUsers.length > 0}
                                                        onChange={(e) => {
                                                            const filteredUsers = roleUsers.filter(u => {
                                                                const matchesSearch = (u.firstName + " " + u.lastName + " " + u.email).toLowerCase().includes(studentSearch.toLowerCase());
                                                                const matchesClass = !classFilter || u.studentClass?.toLowerCase() === classFilter.toLowerCase();
                                                                return matchesSearch && matchesClass;
                                                            });
                                                            if (e.target.checked) {
                                                                setSelectedStudents(filteredUsers.map(u => u.id));
                                                            } else {
                                                                setSelectedStudents([]);
                                                            }
                                                        }}
                                                        className="rounded text-indigo-600 focus:ring-indigo-500/20"
                                                    />
                                                </th>
                                            )}
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest">Name</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest">Email</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest">Phone</th>
                                            {activeView === 'STUDENTS' && <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest">Class</th>}
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest">Status</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest">Joined</th>
                                            <th className="px-8 py-5 text-[10px] font-black text-slate-400 uppercase tracking-widest text-right">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100">
                                        {roleUsers
                                            .filter(u => {
                                                const matchesSearch = (u.firstName + " " + u.lastName + " " + u.email).toLowerCase().includes(studentSearch.toLowerCase());
                                                const matchesClass = !classFilter || u.studentClass?.toLowerCase() === classFilter.toLowerCase();
                                                return matchesSearch && matchesClass;
                                            })
                                            .length === 0 ? (
                                            <tr>
                                                <td colSpan={7} className="px-8 py-20 text-center text-slate-400 font-bold">No {activeView.toLowerCase()} matching filters.</td>
                                            </tr>
                                        ) : (
                                            roleUsers
                                                .filter(u => {
                                                    const matchesSearch = (u.firstName + " " + u.lastName + " " + u.email).toLowerCase().includes(studentSearch.toLowerCase());
                                                    const matchesClass = !classFilter || u.studentClass?.toLowerCase() === classFilter.toLowerCase();
                                                    return matchesSearch && matchesClass;
                                                })
                                                .map(u => (
                                                    <tr key={u.id} className="hover:bg-slate-50/50 transition-colors">
                                                        {activeView === 'STUDENTS' && (
                                                            <td className="px-4 py-5">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={selectedStudents.includes(u.id)}
                                                                    onChange={(e) => {
                                                                        if (e.target.checked) {
                                                                            setSelectedStudents([...selectedStudents, u.id]);
                                                                        } else {
                                                                            setSelectedStudents(selectedStudents.filter(id => id !== u.id));
                                                                        }
                                                                    }}
                                                                    className="rounded text-indigo-600 focus:ring-indigo-500/20"
                                                                />
                                                            </td>
                                                        )}
                                                        <td className="px-8 py-5">
                                                            <div className="flex items-center space-x-3">
                                                                <div className="w-10 h-10 bg-slate-100 rounded-full flex items-center justify-center font-bold text-slate-600">
                                                                    {u.firstName[0]}{u.lastName[0]}
                                                                </div>
                                                                <span className="font-bold text-slate-900">{u.firstName} {u.lastName}</span>
                                                            </div>
                                                        </td>
                                                        <td className="px-8 py-5 text-sm font-medium text-slate-600">{u.email}</td>
                                                        <td className="px-8 py-5 text-sm font-medium text-slate-600">{u.phone || '-'}</td>
                                                        {activeView === 'STUDENTS' && <td className="px-8 py-5">
                                                            <span className="px-3 py-1 bg-slate-100 text-slate-600 rounded-lg text-[10px] font-black uppercase">
                                                                {u.studentClass || 'N/A'}
                                                            </span>
                                                        </td>}
                                                        <td className="px-8 py-5">
                                                            <span className={`px-3 py-1 rounded-full text-[10px] font-black ${u.isActive ? 'bg-emerald-50 text-emerald-600' : 'bg-red-50 text-red-600'}`}>
                                                                {u.isActive ? 'ACTIVE' : 'INACTIVE'}
                                                            </span>
                                                        </td>
                                                        <td className="px-8 py-5 text-sm font-medium text-slate-400">{new Date(u.createdAt).toLocaleDateString()}</td>
                                                        <td className="px-8 py-5">
                                                            <div className="flex items-center justify-end space-x-2">
                                                                <button
                                                                    onClick={(e) => {
                                                                        e.stopPropagation();
                                                                        setEditingUser({ ...u, subjects: u.subjects || [] });
                                                                        setShowEditModal(true);
                                                                    }}
                                                                    className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors border border-transparent hover:border-indigo-100"
                                                                    title="Edit Details"
                                                                >
                                                                    <Edit className="w-4 h-4" />
                                                                </button>
                                                                {activeView === 'STUDENTS' && (
                                                                    <button
                                                                        onClick={(e) => {
                                                                            e.stopPropagation();
                                                                            setPromotingStudent(u);
                                                                            setNewClassForPromotion(u.studentClass || "js1");
                                                                            setShowPromoteModal(true);
                                                                        }}
                                                                        className="p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-lg transition-colors border border-transparent hover:border-emerald-100"
                                                                        title="Promote Student"
                                                                    >
                                                                        <ArrowUpCircle className="w-4 h-4" />
                                                                    </button>
                                                                )}
                                                                {activeView === 'STUDENTS' && u.studentClass?.toLowerCase() === 'ss3' && (
                                                                    <button
                                                                        onClick={(e) => {
                                                                            e.stopPropagation();
                                                                            handleGraduateStudent(u);
                                                                        }}
                                                                        className="p-2 text-slate-400 hover:text-amber-600 hover:bg-amber-50 rounded-lg transition-colors border border-transparent hover:border-amber-100"
                                                                        title="Graduate Student"
                                                                    >
                                                                        <Trophy className="w-4 h-4" />
                                                                    </button>
                                                                )}
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))
                                        )}
                                    </tbody>
                                </table>
                            )}
                            </div>
                        </div>
                    </div>
                )}
            </main>

            {/* Add Employee Modal */}
            {showAddModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                    <div className="w-full max-w-lg bg-white rounded-3xl border border-slate-200 p-8 shadow-2xl max-h-[90vh] overflow-y-auto">
                        <h2 className="text-2xl font-black text-slate-900 mb-6">Add New {newEmployee.role === 'TEACHER' ? 'Teacher' : 'Student'}</h2>
                        <form onSubmit={handleAddEmployee} className="space-y-5">
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Role</label>
                                <select
                                    value={newEmployee.role}
                                    onChange={e => setNewEmployee({ ...newEmployee, role: e.target.value })}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                >
                                    <option value="TEACHER">Teacher</option>
                                    <option value="STUDENT">Student</option>
                                </select>
                            </div>

                            {newEmployee.role === 'STUDENT' && (
                                <div className="space-y-2">
                                    <label className="text-sm font-bold text-slate-600">Class</label>
                                    <select
                                        value={newEmployee.studentClass}
                                        onChange={e => setNewEmployee({ ...newEmployee, studentClass: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    >
                                        <option value="">Select Class</option>
                                        <option value="js1">JS1</option>
                                        <option value="js2">JS2</option>
                                        <option value="js3">JS3</option>
                                        <option value="ss1">SS1</option>
                                        <option value="ss2">SS2</option>
                                        <option value="ss3">SS3</option>
                                        <option value="GRADUATED">GRADUATED</option>
                                    </select>
                                </div>
                            )}

                            {(newEmployee.role === 'TEACHER' || (newEmployee.role === 'STUDENT' && newEmployee.studentClass)) && (
                                <div className="space-y-2">
                                    <label className="text-sm font-bold text-slate-600">Subjects</label>
                                    <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl max-h-60 overflow-y-auto space-y-4">
                                        {['JUNIOR', 'SENIOR'].map(section => {
                                            // Filtering Logic
                                            let showSection = false;
                                            if (newEmployee.role === 'TEACHER') {
                                                showSection = true; // Teachers can see all
                                            } else if (newEmployee.role === 'STUDENT') {
                                                const cl = newEmployee.studentClass.toLowerCase();
                                                const isJunior = cl.startsWith('js');
                                                const isSenior = cl.startsWith('ss');
                                                if (isJunior && section === 'JUNIOR') showSection = true;
                                                if (isSenior && section === 'SENIOR') showSection = true;
                                            }

                                            if (!showSection) return null;

                                            const sectionSubjects = availableSubjects.filter(s => s.section === section);
                                            if (sectionSubjects.length === 0) return null;

                                            // Group by category if Senior
                                            const categories = section === 'SENIOR'
                                                ? Array.from(new Set(sectionSubjects.map(s => s.category))).sort()
                                                : ['General'];

                                            return (
                                                <div key={section} className="space-y-2">
                                                    <h4 className="text-xs font-black text-slate-400 uppercase tracking-widest sticky top-0 bg-slate-50 py-1">{section} Secondary</h4>

                                                    {section === 'SENIOR' ? (
                                                        categories.map((cat: any) => (
                                                            <div key={cat} className="pl-2 border-l-2 border-slate-200">
                                                                <h5 className="text-[10px] font-bold text-indigo-500 mb-1 uppercase">{cat}</h5>
                                                                <div className="grid grid-cols-2 gap-2">
                                                                    {sectionSubjects.filter(s => s.category === cat).map(s => (
                                                                        <label key={s.id} className="flex items-center space-x-2 text-sm font-medium text-slate-700 cursor-pointer">
                                                                            <input
                                                                                type="checkbox"
                                                                                value={s.name}
                                                                                checked={newEmployee.subjects.includes(s.name)}
                                                                                onChange={(e) => {
                                                                                    const checked = e.target.checked;
                                                                                    setNewEmployee(prev => ({
                                                                                        ...prev,
                                                                                        subjects: checked
                                                                                            ? [...prev.subjects, s.name]
                                                                                            : prev.subjects.filter(sub => sub !== s.name)
                                                                                    }));
                                                                                }}
                                                                                className="rounded text-indigo-600 focus:ring-indigo-500/20"
                                                                            />
                                                                            <span className="truncate" title={s.name}>{s.name}</span>
                                                                        </label>
                                                                    ))}
                                                                </div>
                                                            </div>
                                                        ))
                                                    ) : (
                                                        <div className="grid grid-cols-2 gap-2">
                                                            {sectionSubjects.map(s => (
                                                                <label key={s.id} className="flex items-center space-x-2 text-sm font-medium text-slate-700 cursor-pointer">
                                                                    <input
                                                                        type="checkbox"
                                                                        value={s.name}
                                                                        checked={newEmployee.subjects.includes(s.name)}
                                                                        onChange={(e) => {
                                                                            const checked = e.target.checked;
                                                                            setNewEmployee(prev => ({
                                                                                ...prev,
                                                                                subjects: checked
                                                                                    ? [...prev.subjects, s.name]
                                                                                    : prev.subjects.filter(sub => sub !== s.name)
                                                                            }));
                                                                        }}
                                                                        className="rounded text-indigo-600 focus:ring-indigo-500/20"
                                                                    />
                                                                    <span className="truncate" title={s.name}>{s.name}</span>
                                                                </label>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                    <p className="text-xs text-slate-400 font-medium">Selected: {newEmployee.subjects.length}</p>
                                </div>
                            )}

                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="text-sm font-bold text-slate-600">First Name</label>
                                    <input type="text" required placeholder="John" className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20" onChange={e => setNewEmployee({ ...newEmployee, firstName: e.target.value })} />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-sm font-bold text-slate-600">Last Name</label>
                                    <input type="text" required placeholder="Doe" className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20" onChange={e => setNewEmployee({ ...newEmployee, lastName: e.target.value })} />
                                </div>
                            </div>
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Email</label>
                                <input type="email" required placeholder="john@school.com" className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20" onChange={e => setNewEmployee({ ...newEmployee, email: e.target.value })} />
                            </div>
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Phone</label>
                                <input type="tel" placeholder="08012345678" className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20" onChange={e => setNewEmployee({ ...newEmployee, phone: e.target.value })} />
                            </div>
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Address</label>
                                <input type="text" placeholder="123 Street, City" className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20" onChange={e => setNewEmployee({ ...newEmployee, address: e.target.value })} />
                            </div>
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Password</label>
                                <input type="password" required placeholder="••••••••" className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20" onChange={e => setNewEmployee({ ...newEmployee, password: e.target.value })} />
                            </div>
                            <div className="flex justify-end space-x-4 pt-4">
                                <button type="button" onClick={() => setShowAddModal(false)} className="px-5 py-2.5 rounded-xl hover:bg-slate-100 transition-colors font-bold text-slate-600">Cancel</button>
                                <button type="submit" className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 rounded-xl text-white font-bold shadow-lg shadow-indigo-600/20 transition-all">
                                    Add {newEmployee.role === 'TEACHER' ? 'Teacher' : 'Student'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div >
            )
            }

            {/* Bulk Upload Modal */}
            {
                showBulkModal && (
                    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                        <div className="w-full max-w-lg bg-white rounded-3xl border border-slate-200 p-8 shadow-2xl">
                            <h2 className="text-2xl font-black text-slate-900 mb-6">Bulk Student Upload</h2>
                            <div className="space-y-5">
                                <div className="p-6 border-2 border-dashed border-slate-300 rounded-2xl flex flex-col items-center justify-center text-center hover:bg-slate-50 transition-colors">
                                    <Upload className="w-12 h-12 text-slate-400 mb-4" />
                                    <p className="text-sm font-bold text-slate-600 mb-2">Drag and drop your CSV file here</p>
                                    <p className="text-xs text-slate-400 mb-4">or click to browse</p>
                                    <input
                                        type="file"
                                        accept=".csv"
                                        onChange={(e) => setBulkFile(e.target.files ? e.target.files[0] : null)}
                                        className="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100"
                                    />
                                </div>

                                {bulkFile && (
                                    <div className="flex items-center space-x-3 p-4 bg-indigo-50 rounded-xl">
                                        <FileText className="w-5 h-5 text-indigo-600" />
                                        <span className="text-sm font-bold text-indigo-900">{bulkFile.name}</span>
                                    </div>
                                )}

                                <div className="bg-slate-50 p-4 rounded-xl">
                                    <h4 className="text-xs font-black text-slate-500 uppercase tracking-widest mb-2">CSV Format Definition</h4>
                                    <p className="text-xs text-slate-400">Headers: <code className="bg-slate-200 px-1 py-0.5 rounded text-slate-600">firstName, lastName, email, password, studentClass, phone, address</code></p>
                                </div>

                                <div className="flex justify-end space-x-4 pt-4">
                                    <button onClick={() => setShowBulkModal(false)} className="px-5 py-2.5 rounded-xl hover:bg-slate-100 transition-colors font-bold text-slate-600">Cancel</button>
                                    <button
                                        onClick={handleBulkUpload}
                                        disabled={!bulkFile || bulkLoading}
                                        className={`px-6 py-2.5 bg-indigo-600 rounded-xl text-white font-bold shadow-lg shadow-indigo-600/20 transition-all flex items-center space-x-2 ${(!bulkFile || bulkLoading) ? 'opacity-50 cursor-not-allowed' : 'hover:bg-indigo-700'}`}
                                    >
                                        {bulkLoading ? <span>Processing...</span> : <span>Upload Students</span>}
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                )
            }

            {/* Edit User Modal */}
            {showEditModal && editingUser && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                    <div className="w-full max-w-lg bg-white rounded-3xl border border-slate-200 p-8 shadow-2xl max-h-[90vh] overflow-y-auto">
                        <h2 className="text-2xl font-black text-slate-900 mb-6">Edit {editingUser.role === 'TEACHER' ? 'Teacher' : 'Student'}</h2>
                        <form onSubmit={handleUpdateUser} className="space-y-5">

                            {editingUser.role === 'STUDENT' && (
                                <div className="space-y-2">
                                    <label className="text-sm font-bold text-slate-600">Class</label>
                                    <select
                                        value={editingUser.studentClass || ""}
                                        onChange={e => setEditingUser({ ...editingUser, studentClass: e.target.value })}
                                        className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                    >
                                        <option value="">Select Class</option>
                                        <option value="js1">JS1</option>
                                        <option value="js2">JS2</option>
                                        <option value="js3">JS3</option>
                                        <option value="ss1">SS1</option>
                                        <option value="ss2">SS2</option>
                                        <option value="ss3">SS3</option>
                                        <option value="GRADUATED">GRADUATED</option>
                                    </select>
                                </div>
                            )}

                            {(editingUser.role === 'TEACHER' || (editingUser.role === 'STUDENT' && editingUser.studentClass)) && (
                                <div className="space-y-2">
                                    <label className="text-sm font-bold text-slate-600">Subjects</label>
                                    <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl max-h-60 overflow-y-auto space-y-4">
                                        {['JUNIOR', 'SENIOR'].map(section => {
                                            // Filtering Logic
                                            let showSection = false;
                                            if (editingUser.role === 'TEACHER') {
                                                showSection = true; // Teachers can see all
                                            } else if (editingUser.role === 'STUDENT') {
                                                const cl = (editingUser.studentClass || '').toLowerCase();
                                                const isJunior = cl.startsWith('js');
                                                const isSenior = cl.startsWith('ss');
                                                if (isJunior && section === 'JUNIOR') showSection = true;
                                                if (isSenior && section === 'SENIOR') showSection = true;
                                            }

                                            if (!showSection) return null;

                                            const sectionSubjects = availableSubjects.filter(s => s.section === section);
                                            if (sectionSubjects.length === 0) return null;

                                            // Group by category if Senior
                                            const categories = section === 'SENIOR'
                                                ? Array.from(new Set(sectionSubjects.map(s => s.category))).sort()
                                                : ['General'];

                                            return (
                                                <div key={section} className="space-y-2">
                                                    <h4 className="text-xs font-black text-slate-400 uppercase tracking-widest sticky top-0 bg-slate-50 py-1">{section} Secondary</h4>

                                                    {section === 'SENIOR' ? (
                                                        categories.map((cat: any) => (
                                                            <div key={cat} className="pl-2 border-l-2 border-slate-200">
                                                                <h5 className="text-[10px] font-bold text-indigo-500 mb-1 uppercase">{cat}</h5>
                                                                <div className="grid grid-cols-2 gap-2">
                                                                    {sectionSubjects.filter(s => s.category === cat).map(s => (
                                                                        <label key={s.id} className="flex items-center space-x-2 text-sm font-medium text-slate-700 cursor-pointer">
                                                                            <input
                                                                                type="checkbox"
                                                                                value={s.name}
                                                                                checked={editingUser.subjects?.includes(s.name)}
                                                                                onChange={(e) => {
                                                                                    const checked = e.target.checked;
                                                                                    const currentSubjects = editingUser.subjects || [];
                                                                                    setEditingUser({
                                                                                        ...editingUser,
                                                                                        subjects: checked
                                                                                            ? [...currentSubjects, s.name]
                                                                                            : currentSubjects.filter((sub: string) => sub !== s.name)
                                                                                    });
                                                                                }}
                                                                                className="rounded text-indigo-600 focus:ring-indigo-500/20"
                                                                            />
                                                                            <span className="truncate" title={s.name}>{s.name}</span>
                                                                        </label>
                                                                    ))}
                                                                </div>
                                                            </div>
                                                        ))
                                                    ) : (
                                                        <div className="grid grid-cols-2 gap-2">
                                                            {sectionSubjects.map(s => (
                                                                <label key={s.id} className="flex items-center space-x-2 text-sm font-medium text-slate-700 cursor-pointer">
                                                                    <input
                                                                        type="checkbox"
                                                                        value={s.name}
                                                                        checked={editingUser.subjects?.includes(s.name)}
                                                                        onChange={(e) => {
                                                                            const checked = e.target.checked;
                                                                            const currentSubjects = editingUser.subjects || [];
                                                                            setEditingUser({
                                                                                ...editingUser,
                                                                                subjects: checked
                                                                                    ? [...currentSubjects, s.name]
                                                                                    : currentSubjects.filter((sub: string) => sub !== s.name)
                                                                            });
                                                                        }}
                                                                        className="rounded text-indigo-600 focus:ring-indigo-500/20"
                                                                    />
                                                                    <span className="truncate" title={s.name}>{s.name}</span>
                                                                </label>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                    <p className="text-xs text-slate-400 font-medium">Selected: {editingUser.subjects?.length || 0}</p>
                                </div>
                            )}

                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="text-sm font-bold text-slate-600">First Name</label>
                                    <input type="text" required value={editingUser.firstName} className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20" onChange={e => setEditingUser({ ...editingUser, firstName: e.target.value })} />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-sm font-bold text-slate-600">Last Name</label>
                                    <input type="text" required value={editingUser.lastName} className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20" onChange={e => setEditingUser({ ...editingUser, lastName: e.target.value })} />
                                </div>
                            </div>

                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Phone</label>
                                <input type="tel" value={editingUser.phone || ""} className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20" onChange={e => setEditingUser({ ...editingUser, phone: e.target.value })} />
                            </div>
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Address</label>
                                <input type="text" value={editingUser.address || ""} className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20" onChange={e => setEditingUser({ ...editingUser, address: e.target.value })} />
                            </div>

                            <div className="flex justify-end space-x-4 pt-4">
                                <button type="button" onClick={() => setShowEditModal(false)} className="px-5 py-2.5 rounded-xl hover:bg-slate-100 transition-colors font-bold text-slate-600">Cancel</button>
                                <button type="submit" className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 rounded-xl text-white font-bold shadow-lg shadow-indigo-600/20 transition-all">
                                    Save Changes
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Add Subject Modal */}
            {showAddSubjectModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                    <div className="w-full max-w-md bg-white rounded-3xl border border-slate-200 p-8 shadow-2xl">
                        <h2 className="text-2xl font-black text-slate-900 mb-6">Add New Subject</h2>
                        <form onSubmit={async (e) => {
                            e.preventDefault();
                            try {
                                const token = localStorage.getItem("token");
                                const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/subjects`, {
                                    method: "POST",
                                    headers: {
                                        "Content-Type": "application/json",
                                        Authorization: `Bearer ${token}`
                                    },
                                    body: JSON.stringify(newSubject)
                                });
                                if (res.ok) {
                                    const data = await res.json();
                                    setAvailableSubjects([...availableSubjects, data]);
                                    setShowAddSubjectModal(false);
                                    setNewSubject({ name: "", section: "JUNIOR", category: "" });
                                    setFeedback({ type: 'success', message: 'Subject added to curriculum!' });
                                    setTimeout(() => setFeedback(null), 3000);
                                } else {
                                    const data = await res.json();
                                    setFeedback({ type: 'error', message: data.error || 'Failed to add subject' });
                                }
                            } catch (err) {
                                setFeedback({ type: 'error', message: 'Network error' });
                            }
                        }} className="space-y-4">
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Subject Name</label>
                                <input
                                    type="text"
                                    required
                                    placeholder="e.g. Further Mathematics"
                                    value={newSubject.name}
                                    onChange={e => setNewSubject({ ...newSubject, name: e.target.value })}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                />
                            </div>
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Section</label>
                                <select
                                    value={newSubject.section}
                                    onChange={e => setNewSubject({ ...newSubject, section: e.target.value })}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                >
                                    <option value="JUNIOR">Junior Secondary</option>
                                    <option value="SENIOR">Senior Secondary</option>
                                </select>
                            </div>
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Category (For Senior)</label>
                                <input
                                    type="text"
                                    placeholder="e.g. Science, Arts, Commercial"
                                    value={newSubject.category}
                                    onChange={e => setNewSubject({ ...newSubject, category: e.target.value })}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                />
                            </div>
                            <div className="flex justify-end space-x-4 pt-4">
                                <button type="button" onClick={() => setShowAddSubjectModal(false)} className="px-5 py-2.5 rounded-xl hover:bg-slate-100 transition-colors font-bold text-slate-600">Cancel</button>
                                <button type="submit" className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 rounded-xl text-white font-bold shadow-lg shadow-indigo-600/20 transition-all">
                                    Add Subject
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
            {/* Promotion Modal */}
            {showPromoteModal && promotingStudent && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                    <div className="w-full max-w-md bg-white rounded-3xl border border-slate-200 p-8 shadow-2xl">
                        <h2 className="text-2xl font-black text-slate-900 mb-2">Promote Student</h2>
                        <p className="text-sm text-slate-500 font-medium mb-6">Moving <span className="text-indigo-600 font-bold">{promotingStudent.firstName} {promotingStudent.lastName}</span> to a new class.</p>

                        <div className="space-y-6">
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">Select New Class</label>
                                <select
                                    value={newClassForPromotion}
                                    onChange={e => setNewClassForPromotion(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                >
                                    <option value="js1">JS1</option>
                                    <option value="js2">JS2</option>
                                    <option value="js3">JS3</option>
                                    <option value="ss1">SS1</option>
                                    <option value="ss2">SS2</option>
                                    <option value="ss3">SS3</option>
                                    <option value="GRADUATED">GRADUATED</option>
                                </select>
                            </div>

                            <div className="p-4 bg-amber-50 rounded-2xl border border-amber-100">
                                <p className="text-xs text-amber-700 font-bold flex items-center">
                                    <span className="mr-2">⚠️</span>
                                    {newClassForPromotion.startsWith('ss') && (promotingStudent.studentClass || '').startsWith('js')
                                        ? "Moving from Junior to Senior section will clear all currently assigned subjects."
                                        : "This will update the student's official record."
                                    }
                                </p>
                            </div>

                            <div className="flex justify-end space-x-4 pt-4">
                                <button onClick={() => setShowPromoteModal(false)} className="px-5 py-2.5 rounded-xl hover:bg-slate-100 transition-colors font-bold text-slate-600">Cancel</button>
                                <button
                                    onClick={async () => {
                                        try {
                                            const token = localStorage.getItem("token");

                                            // Check for section switch
                                            const oldSection = (promotingStudent.studentClass || '').startsWith('js') ? 'JSS' : 'SSS';
                                            const newSection = newClassForPromotion.startsWith('js') ? 'JSS' : 'SSS';

                                            const updatedData = {
                                                ...promotingStudent,
                                                studentClass: newClassForPromotion,
                                                subjects: oldSection !== newSection ? [] : promotingStudent.subjects
                                            };

                                            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/users/${promotingStudent.id}`, {
                                                method: "PUT",
                                                headers: {
                                                    "Content-Type": "application/json",
                                                    Authorization: `Bearer ${token}`
                                                },
                                                body: JSON.stringify(updatedData)
                                            });

                                            if (res.ok) {
                                                setFeedback({ type: 'success', message: 'Student promoted successfully!' });
                                                fetchUsers('STUDENT');
                                                setShowPromoteModal(false);
                                                setTimeout(() => setFeedback(null), 3000);
                                            } else {
                                                const data = await res.json();
                                                setFeedback({ type: 'error', message: data.error || 'Promotion failed' });
                                            }
                                        } catch (err) {
                                            setFeedback({ type: 'error', message: 'Network error' });
                                        }
                                    }}
                                    className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-700 rounded-xl text-white font-bold shadow-lg shadow-emerald-600/20 transition-all"
                                >
                                    Confirm Promotion
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Bulk Promote Modal */}
            {showBulkPromoteModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                    <div className="w-full max-w-md bg-white rounded-3xl border border-slate-200 p-8 shadow-2xl">
                        <h2 className="text-2xl font-black text-slate-900 mb-2">Bulk Promote Students</h2>
                        <p className="text-sm text-slate-500 mb-6">
                            Promote or demote {selectedStudents.length} selected student{selectedStudents.length !== 1 ? 's' : ''} to a new class.
                        </p>
                        <div className="space-y-4">
                            <div className="space-y-2">
                                <label className="text-sm font-bold text-slate-600">New Class</label>
                                <select
                                    value={bulkPromoteClass}
                                    onChange={e => setBulkPromoteClass(e.target.value)}
                                    className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3 text-slate-900 font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                                >
                                    <option value="">Select Class</option>
                                    <option value="js1">JS1</option>
                                    <option value="js2">JS2</option>
                                    <option value="js3">JS3</option>
                                    <option value="ss1">SS1</option>
                                    <option value="ss2">SS2</option>
                                    <option value="ss3">SS3</option>
                                    <option value="GRADUATED">GRADUATED</option>
                                </select>
                            </div>
                            <div className="flex items-center justify-end space-x-3 pt-4">
                                <button
                                    onClick={() => {
                                        setShowBulkPromoteModal(false);
                                        setBulkPromoteClass("");
                                    }}
                                    className="px-5 py-2.5 rounded-xl hover:bg-slate-100 transition-colors font-bold text-slate-600"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleBulkPromote}
                                    className="px-6 py-2.5 bg-purple-600 hover:bg-purple-700 rounded-xl text-white font-bold shadow-lg shadow-purple-600/20 transition-all"
                                >
                                    Promote Students
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div >
    );
}

function NavItem({ icon, label, active = false, onClick }: { icon: any, label: string, active?: boolean, onClick?: () => void }) {
    return (
        <button onClick={onClick} className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition-all group ${active ? 'bg-indigo-50 text-indigo-600 shadow-sm' : 'text-slate-500 hover:bg-slate-50 hover:text-slate-900'
            }`}>
            <span className={`w-5 h-5 ${active ? 'text-indigo-600' : 'text-slate-400 group-hover:text-slate-600'} transition-colors`}>{icon}</span>
            <span className="font-bold text-sm">{label}</span>
            {active && <div className="ml-auto w-1 h-5 bg-indigo-600 rounded-full" />}
        </button>
    );
}

function AdminStatCard({ title, value, trend, icon, color }: { title: string, value: string, trend: string, icon: any, color: string }) {
    const colorMap: any = {
        blue: "bg-blue-50 border-blue-100",
        purple: "bg-purple-50 border-purple-100",
        emerald: "bg-emerald-50 border-emerald-100",
    };

    return (
        <div className="bg-white p-8 rounded-[2.5rem] border border-slate-200 shadow-sm hover:shadow-xl hover:shadow-slate-200 transition-all duration-300">
            <div className="flex items-center justify-between mb-6">
                <div className={`p-4 rounded-2xl ${colorMap[color]} text-2xl`}>{icon}</div>
                <div className="bg-emerald-50 text-emerald-600 px-3 py-1 rounded-full text-xs font-black">{trend}%</div>
            </div>
            <div>
                <h3 className="text-4xl font-black text-slate-900 mb-1">{value}</h3>
                <p className="text-sm font-bold text-slate-400 uppercase tracking-widest">{title}</p>
            </div>
        </div>
    );
}

function QuickActionItem({ icon, label }: { icon: any, label: string }) {
    return (
        <button className="w-full flex items-center justify-between p-4 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-2xl transition-all group text-left">
            <div className="flex items-center space-x-4">
                <div className="p-2 bg-white rounded-lg shadow-sm">{icon}</div>
                <span className="font-bold text-slate-700 text-sm">{label}</span>
            </div>
            <ArrowUpRight className="w-4 h-4 text-slate-300 group-hover:text-slate-900 transition-colors" />
        </button>
    );
}
