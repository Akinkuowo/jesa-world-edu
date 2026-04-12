"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, BookOpen, Search, Download, ExternalLink, LibrarySquare, Bookmark } from "lucide-react";

interface DigitalBook {
    id: string;
    title: string;
    author: string;
    category: string;
    description: string | null;
    coverUrl: string | null;
    downloadLink: string;
    createdAt: string;
}

export default function StudentLibrary() {
    const router = useRouter();
    const [books, setBooks] = useState<DigitalBook[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState("");
    const [activeCategory, setActiveCategory] = useState("All");

    useEffect(() => {
        fetchBooks();
    }, []);

    const fetchBooks = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/student/library`, {
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

    // Extract unique categories
    const categories = ["All", ...Array.from(new Set(books.map(b => b.category)))];

    const filteredBooks = books.filter(book => {
        const matchesSearch = book.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
                              book.author.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesCategory = activeCategory === "All" || book.category === activeCategory;
        return matchesSearch && matchesCategory;
    });

    return (
        <div className="min-h-screen bg-[#f1f3f6] text-slate-900 font-sans pb-20">
            {/* Header Banner */}
            <div className="bg-indigo-700 h-64 lg:h-72 w-full relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-r from-indigo-700 to-fuchsia-700 opacity-90" />
                <div className="absolute -right-20 -top-20 w-80 h-80 bg-white/10 rounded-full blur-3xl" />
                <div className="absolute -left-20 -bottom-20 w-80 h-80 bg-white/10 rounded-full blur-3xl" />
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-full bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-10 mix-blend-overlay" />

                <div className="relative z-10 max-w-7xl mx-auto px-6 lg:px-10 h-full flex flex-col justify-center pt-8">
                    <button onClick={() => router.push('/dashboard/student')} className="absolute top-8 left-6 lg:left-10 p-2.5 bg-white/10 hover:bg-white/20 text-white rounded-xl transition-all flex items-center space-x-2 text-sm font-bold backdrop-blur-sm shadow-sm border border-white/5">
                        <ArrowLeft className="w-4 h-4" />
                        <span>Back to Dashboard</span>
                    </button>
                    
                    <div className="flex flex-col lg:flex-row items-center justify-between gap-6">
                        <div className="flex items-center space-x-5 text-white">
                            <div className="w-20 h-20 bg-white/10 rounded-3xl p-1 shadow-2xl flex items-center justify-center backdrop-blur-md border border-white/20">
                                <LibrarySquare className="w-10 h-10 text-white" />
                            </div>
                            <div>
                                <h1 className="text-3xl lg:text-5xl font-black tracking-tight mb-2 drop-shadow-sm">Digital Library</h1>
                                <p className="opacity-90 font-medium text-sm lg:text-lg tracking-wide">Explore our curated collection of educational resources.</p>
                            </div>
                        </div>

                        {/* Search Bar */}
                        <div className="w-full lg:w-96 relative">
                            <Search className="absolute left-5 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                            <input 
                                type="text"
                                value={searchQuery}
                                onChange={e => setSearchQuery(e.target.value)}
                                placeholder="Search books, authors..."
                                className="w-full pl-14 pr-6 py-4 bg-white rounded-2xl shadow-2xl shadow-indigo-900/20 text-sm font-bold outline-none focus:ring-4 focus:ring-white/20 transition-all text-slate-800"
                            />
                        </div>
                    </div>
                </div>
            </div>

            {/* Main Content */}
            <div className="max-w-7xl mx-auto px-6 lg:px-10 -mt-8 relative z-20">
                <div className="bg-white rounded-[2.5rem] p-8 lg:p-10 shadow-xl shadow-slate-200/60 border border-white min-h-[60vh]">
                    
                    {/* Category Filter */}
                    {categories.length > 1 && (
                        <div className="flex items-center gap-3 overflow-x-auto pb-6 mb-8 custom-scrollbar border-b border-slate-100">
                            {categories.map(category => (
                                <button 
                                    key={category}
                                    onClick={() => setActiveCategory(category)}
                                    className={`px-6 py-2.5 rounded-full font-black text-xs uppercase tracking-widest whitespace-nowrap transition-all duration-300 ${activeCategory === category ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20 scale-105' : 'bg-slate-50 text-slate-500 hover:bg-slate-100'}`}
                                >
                                    {category}
                                </button>
                            ))}
                        </div>
                    )}

                    {loading ? (
                        <div className="flex flex-col items-center justify-center py-20 text-indigo-400">
                            <div className="w-12 h-12 border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin mb-4 shadow-xl" />
                            <p className="font-black text-sm uppercase tracking-widest">Loading Catalog...</p>
                        </div>
                    ) : filteredBooks.length > 0 ? (
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6 lg:gap-8">
                            {filteredBooks.map((book) => (
                                <div key={book.id} className="group flex flex-col bg-white rounded-[2rem] border border-slate-100 overflow-hidden hover:shadow-2xl hover:shadow-indigo-500/10 hover:-translate-y-2 transition-all duration-500">
                                    
                                    {/* Cover Placeholder / Gradient */}
                                    <div className="h-48 w-full bg-slate-100 relative overflow-hidden p-6 flex flex-col justify-between">
                                        <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 to-fuchsia-500/5 group-hover:scale-110 transition-transform duration-700" />
                                        
                                        <div className="relative z-10 flex justify-between items-start">
                                            <span className="px-3 py-1 bg-white/80 backdrop-blur-sm text-indigo-700 rounded-full text-[9px] font-black uppercase tracking-widest shadow-sm">
                                                {book.category}
                                            </span>
                                            <div className="w-8 h-8 rounded-full bg-white/80 backdrop-blur-sm flex items-center justify-center text-slate-400 opacity-0 group-hover:opacity-100 transform translate-y-2 group-hover:translate-y-0 transition-all duration-300 shadow-sm">
                                                <Bookmark className="w-3.5 h-3.5" />
                                            </div>
                                        </div>

                                        <BookOpen className="w-12 h-12 text-slate-300 relative z-10 opacity-50 group-hover:scale-110 group-hover:rotate-12 transition-all duration-500" />
                                    </div>
                                    
                                    {/* Details */}
                                    <div className="p-6 flex flex-col flex-1">
                                        <h3 className="text-xl font-black text-slate-900 mb-1 leading-tight group-hover:text-indigo-600 transition-colors line-clamp-2">{book.title}</h3>
                                        <p className="text-xs font-bold text-slate-400 mb-4 tracking-wide">{book.author}</p>
                                        
                                        <div className="mt-auto pt-6 border-t border-slate-100/60">
                                            <a 
                                                href={book.downloadLink} 
                                                target="_blank" 
                                                rel="noreferrer" 
                                                className="w-full flex items-center justify-center gap-2 bg-indigo-50 hover:bg-indigo-600 text-indigo-600 hover:text-white py-3 rounded-xl font-black text-[11px] uppercase tracking-widest transition-all duration-300 group/btn"
                                            >
                                                <ExternalLink className="w-4 h-4 group-hover/btn:scale-110 transition-transform" /> Access Material
                                            </a>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="py-24 flex flex-col items-center justify-center border-2 border-dashed border-slate-100 rounded-[2.5rem] bg-slate-50/50">
                            <Search className="w-16 h-16 text-slate-200 mb-4" />
                            <h3 className="text-xl font-black text-slate-800 mb-2">No match found</h3>
                            <p className="text-sm text-slate-500 font-medium">Try adjusting your search criteria or modifying filters.</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
