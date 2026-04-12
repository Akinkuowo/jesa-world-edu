"use client";

import { useState, useEffect } from "react";
import { BookOpen, X, Plus, Trash2, Link as LinkIcon, CheckCircle2 } from "lucide-react";

interface LibraryModalProps {
    isOpen: boolean;
    onClose: () => void;
    schoolId: string;
}

export default function LibraryModal({ isOpen, onClose, schoolId }: LibraryModalProps) {
    const [books, setBooks] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [adding, setAdding] = useState(false);
    const [newBook, setNewBook] = useState({ title: '', author: '', category: 'Science', downloadLink: '' });
    const [toast, setToast] = useState<{show: boolean, message: string}>({show: false, message: ''});

    useEffect(() => {
        if (isOpen) {
            fetchBooks();
        }
    }, [isOpen, schoolId]);

    const fetchBooks = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/library`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                setBooks(await res.json());
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const handleAddBook = async (e: React.FormEvent) => {
        e.preventDefault();
        setAdding(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/library`, {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(newBook)
            });

            if (res.ok) {
                setToast({show: true, message: 'Book successfully added to the digital catalog!'});
                setTimeout(() => setToast({show: false, message: ''}), 3000);
                setNewBook({ title: '', author: '', category: 'Science', downloadLink: '' });
                fetchBooks();
            }
        } catch (err) {
            console.error(err);
        } finally {
            setAdding(false);
        }
    };

    const handleDeleteBook = async (id: string) => {
        if (!confirm("Are you sure you want to remove this book from the library?")) return;
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/admin/library/${id}`, {
                method: "DELETE",
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                fetchBooks();
            }
        } catch (err) {
            console.error(err);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
            <div className="bg-white w-full max-w-5xl max-h-[90vh] rounded-[2.5rem] flex flex-col shadow-2xl overflow-hidden scale-100 animate-in zoom-in-95 duration-200">
                
                {/* Header */}
                <div className="px-8 py-6 border-b border-slate-100 flex items-center justify-between bg-slate-50 shrink-0">
                    <div className="flex items-center gap-4">
                        <div className="w-12 h-12 bg-indigo-100 text-indigo-600 rounded-2xl flex items-center justify-center shadow-inner">
                            <BookOpen className="w-6 h-6" />
                        </div>
                        <div>
                            <h2 className="text-2xl font-black text-slate-900 leading-tight">Digital Library Management</h2>
                            <p className="text-sm font-bold text-slate-500 uppercase tracking-widest mt-0.5">Manage School eBooks & Resources</p>
                        </div>
                    </div>
                    <button onClick={onClose} className="p-2 hover:bg-slate-200 rounded-full transition-colors">
                        <X className="w-6 h-6 text-slate-500" />
                    </button>
                </div>

                {/* Body */}
                <div className="flex-1 overflow-y-auto p-8 custom-scrollbar bg-white">
                    {toast.show && (
                        <div className="mb-6 p-4 bg-emerald-50 text-emerald-800 rounded-2xl flex items-center gap-3 border border-emerald-100 animate-in slide-in-from-top-2">
                            <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                            <span className="font-bold text-sm">{toast.message}</span>
                        </div>
                    )}

                    <div className="grid lg:grid-cols-3 gap-8">
                        {/* Upload Form */}
                        <div className="lg:col-span-1">
                            <form onSubmit={handleAddBook} className="bg-slate-50 rounded-3xl p-6 border border-slate-100 sticky top-0">
                                <h3 className="text-sm font-black text-slate-900 uppercase tracking-widest mb-6 flex items-center gap-2">
                                    <Plus className="w-4 h-4 text-indigo-500" /> Add New Resource
                                </h3>
                                
                                <div className="space-y-4">
                                    <div>
                                        <label className="text-[10px] font-black uppercase tracking-widest text-slate-400 ml-1">Book Title</label>
                                        <input required value={newBook.title} onChange={e => setNewBook({...newBook, title: e.target.value})} className="w-full mt-1 bg-white border border-slate-200 rounded-xl px-4 py-3 outline-none focus:border-indigo-500 text-sm font-bold transition-all" placeholder="e.g. Advanced Physics" />
                                    </div>
                                    <div>
                                        <label className="text-[10px] font-black uppercase tracking-widest text-slate-400 ml-1">Author / Publisher</label>
                                        <input required value={newBook.author} onChange={e => setNewBook({...newBook, author: e.target.value})} className="w-full mt-1 bg-white border border-slate-200 rounded-xl px-4 py-3 outline-none focus:border-indigo-500 text-sm font-bold transition-all" placeholder="e.g. Isaac Newton" />
                                    </div>
                                    <div>
                                        <label className="text-[10px] font-black uppercase tracking-widest text-slate-400 ml-1">Category</label>
                                        <select value={newBook.category} onChange={e => setNewBook({...newBook, category: e.target.value})} className="w-full mt-1 bg-white border border-slate-200 rounded-xl px-4 py-3 outline-none focus:border-indigo-500 text-sm font-bold transition-all">
                                            <option value="Science">Science & Math</option>
                                            <option value="Arts & Humanities">Arts & Humanities</option>
                                            <option value="Languages">Languages</option>
                                            <option value="Fiction">Fiction</option>
                                            <option value="Exam Prep">Exam Preparation</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label className="text-[10px] font-black uppercase tracking-widest text-slate-400 ml-1 flex items-center gap-1">
                                            <LinkIcon className="w-3 h-3" /> External Link (PDF/Drive)
                                        </label>
                                        <input required type="url" value={newBook.downloadLink} onChange={e => setNewBook({...newBook, downloadLink: e.target.value})} className="w-full mt-1 bg-white border border-slate-200 rounded-xl px-4 py-3 outline-none focus:border-indigo-500 text-sm font-bold transition-all" placeholder="https://drive.google.com/..." />
                                    </div>

                                    <button disabled={adding} className="w-full mt-4 bg-indigo-600 text-white rounded-xl py-4 font-black uppercase tracking-widest text-xs hover:bg-indigo-700 transition-all shadow-md shadow-indigo-500/20 disabled:opacity-50">
                                        {adding ? 'Uploading...' : 'Upload Resource'}
                                    </button>
                                </div>
                            </form>
                        </div>

                        {/* Roster View */}
                        <div className="lg:col-span-2">
                            {loading ? (
                                <div className="py-20 text-center text-slate-400 font-bold uppercase tracking-widest text-sm">Loading Catalog...</div>
                            ) : books.length > 0 ? (
                                <div className="grid sm:grid-cols-2 gap-4">
                                    {books.map((book) => (
                                        <div key={book.id} className="p-5 border border-slate-100 rounded-[2rem] hover:shadow-lg transition-all bg-white group flex flex-col">
                                            <div className="flex justify-between items-start mb-3">
                                                <span className="px-2.5 py-0.5 bg-indigo-50 text-indigo-600 rounded-full text-[9px] font-black uppercase tracking-widest">
                                                    {book.category}
                                                </span>
                                                <button onClick={() => handleDeleteBook(book.id)} className="opacity-0 group-hover:opacity-100 text-slate-300 hover:text-red-500 transition-all">
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                            <h4 className="font-black text-slate-900 mb-1 leading-tight">{book.title}</h4>
                                            <p className="text-xs font-bold text-slate-400 mb-6">{book.author}</p>
                                            
                                            <div className="mt-auto">
                                                <a href={book.downloadLink} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs font-black uppercase tracking-wide text-indigo-600 hover:text-indigo-800 bg-indigo-50/50 px-3 py-1.5 rounded-lg">
                                                    <LinkIcon className="w-3 h-3" /> View / Download
                                                </a>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="py-20 flex flex-col items-center justify-center text-center border-2 border-dashed border-slate-100 rounded-[2rem]">
                                    <BookOpen className="w-12 h-12 text-slate-200 mb-4" />
                                    <h4 className="text-slate-800 font-black mb-1">Catalog Empty</h4>
                                    <p className="text-xs font-bold tracking-wide text-slate-400 uppercase">Upload resources to build your library.</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
