"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { Send, MessageCircle, Search, User, Circle, ChevronLeft } from "lucide-react";

interface Contact {
    id: string;
    firstName: string;
    lastName: string;
    role: string;
    studentClass: string | null;
}

interface ChatMessage {
    id: string;
    senderId: string;
    receiverId: string;
    content: string;
    isRead: boolean;
    createdAt: string;
}

export default function TeacherChat() {
    const router = useRouter();
    const [contacts, setContacts] = useState<Contact[]>([]);
    const [selectedContact, setSelectedContact] = useState<Contact | null>(null);
    const [messages, setMessages] = useState<ChatMessage[]>([]);
    const [newMessage, setNewMessage] = useState("");
    const [loading, setLoading] = useState(true);
    const [sending, setSending] = useState(false);
    const [searchQuery, setSearchQuery] = useState("");
    const [currentUserId, setCurrentUserId] = useState("");
    const [showMobileContacts, setShowMobileContacts] = useState(true);
    const [filterRole, setFilterRole] = useState<"ALL" | "STUDENT" | "TEACHER">("ALL");
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const pollingRef = useRef<NodeJS.Timeout | null>(null);

    useEffect(() => {
        const token = localStorage.getItem("token");
        if (!token) { router.push("/login"); return; }
        try {
            const payload = JSON.parse(atob(token.split(".")[1]));
            setCurrentUserId(payload.id);
        } catch {}
        fetchContacts();
    }, []);

    useEffect(() => {
        if (selectedContact) {
            fetchMessages(selectedContact.id);
            pollingRef.current = setInterval(() => {
                fetchMessages(selectedContact.id, true);
            }, 5000);
        }
        return () => {
            if (pollingRef.current) clearInterval(pollingRef.current);
        };
    }, [selectedContact]);

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    const fetchContacts = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/chat/contacts`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) setContacts(await res.json());
        } catch (err) { console.error(err); }
        finally { setLoading(false); }
    };

    const fetchMessages = async (contactId: string, silent = false) => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/chat/messages/${contactId}`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) setMessages(await res.json());
        } catch (err) { console.error(err); }
    };

    const handleSend = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!newMessage.trim() || !selectedContact || sending) return;
        setSending(true);
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/chat/messages`, {
                method: "POST",
                headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
                body: JSON.stringify({ receiverId: selectedContact.id, content: newMessage.trim() })
            });
            if (res.ok) {
                setNewMessage("");
                fetchMessages(selectedContact.id, true);
            }
        } catch (err) { console.error(err); }
        finally { setSending(false); }
    };

    const selectContact = (contact: Contact) => {
        setSelectedContact(contact);
        setShowMobileContacts(false);
    };

    const filteredContacts = contacts.filter(c => {
        const matchesSearch = `${c.firstName} ${c.lastName}`.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesRole = filterRole === "ALL" || c.role === filterRole;
        return matchesSearch && matchesRole;
    });

    const formatTime = (dateStr: string) => {
        const d = new Date(dateStr);
        return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    };

    const formatDate = (dateStr: string) => {
        const d = new Date(dateStr);
        const today = new Date();
        if (d.toDateString() === today.toDateString()) return "Today";
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
        return d.toLocaleDateString([], { month: "short", day: "numeric" });
    };

    const groupedMessages: { date: string; msgs: ChatMessage[] }[] = [];
    messages.forEach(msg => {
        const dateKey = formatDate(msg.createdAt);
        const existing = groupedMessages.find(g => g.date === dateKey);
        if (existing) existing.msgs.push(msg);
        else groupedMessages.push({ date: dateKey, msgs: [msg] });
    });

    return (
        <div className="h-[calc(100vh-80px)] flex overflow-hidden rounded-[2rem] border border-slate-200 bg-white shadow-sm">
            {/* Contacts Sidebar */}
            <div className={`w-full lg:w-96 bg-white border-r border-slate-100 flex flex-col shrink-0 ${!showMobileContacts ? 'hidden lg:flex' : 'flex'}`}>
                {/* Search & Filter */}
                <div className="p-4 border-b border-slate-50 space-y-3">
                    <div className="relative">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-300" />
                        <input
                            value={searchQuery}
                            onChange={e => setSearchQuery(e.target.value)}
                            placeholder="Search contacts..."
                            className="w-full pl-11 pr-4 py-3 bg-slate-50 rounded-xl text-sm font-bold outline-none focus:bg-slate-100 transition-all text-slate-700 placeholder:text-slate-300"
                        />
                    </div>
                    <div className="flex gap-2">
                        {(["ALL", "STUDENT", "TEACHER"] as const).map(role => (
                            <button
                                key={role}
                                onClick={() => setFilterRole(role)}
                                className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${filterRole === role ? 'bg-indigo-600 text-white shadow-md shadow-indigo-500/20' : 'bg-slate-50 text-slate-400 hover:bg-slate-100'}`}
                            >
                                {role === "ALL" ? "All" : role === "STUDENT" ? "Students" : "Teachers"}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Contact List */}
                <div className="flex-1 overflow-y-auto">
                    {loading ? (
                        <div className="flex flex-col items-center justify-center py-20 text-slate-300">
                            <div className="w-8 h-8 border-[3px] border-slate-200 border-t-indigo-500 rounded-full animate-spin mb-3" />
                            <p className="text-[10px] font-black uppercase tracking-widest">Loading...</p>
                        </div>
                    ) : filteredContacts.length > 0 ? (
                        filteredContacts.map(contact => (
                            <button
                                key={contact.id}
                                onClick={() => selectContact(contact)}
                                className={`w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-slate-50 transition-all border-b border-slate-50/80 ${selectedContact?.id === contact.id ? 'bg-indigo-50/60 border-l-4 border-l-indigo-500' : ''}`}
                            >
                                <div className="relative">
                                    <div className={`w-12 h-12 rounded-2xl flex items-center justify-center text-white font-black text-sm shadow-lg ${contact.role === 'STUDENT' ? 'bg-gradient-to-br from-emerald-400 to-teal-500 shadow-emerald-500/20' : 'bg-gradient-to-br from-indigo-400 to-purple-500 shadow-indigo-500/20'}`}>
                                        {contact.firstName[0]}{contact.lastName[0]}
                                    </div>
                                    <Circle className="absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 text-emerald-400 fill-emerald-400" />
                                </div>
                                <div className="flex-1 min-w-0">
                                    <h4 className="font-bold text-slate-900 text-sm truncate">{contact.firstName} {contact.lastName}</h4>
                                    <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                                        {contact.role}{contact.studentClass ? ` · ${contact.studentClass}` : ''}
                                    </p>
                                </div>
                            </button>
                        ))
                    ) : (
                        <div className="py-20 flex flex-col items-center text-center px-8">
                            <User className="w-12 h-12 text-slate-200 mb-3" />
                            <p className="text-sm font-bold text-slate-400">No contacts found</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Chat Panel */}
            <div className={`flex-1 flex flex-col bg-[#f8f9fc] ${showMobileContacts ? 'hidden lg:flex' : 'flex'}`}>
                {selectedContact ? (
                    <>
                        {/* Chat Header */}
                        <div className="bg-white px-6 py-4 border-b border-slate-100 flex items-center gap-4 shrink-0">
                            <button onClick={() => setShowMobileContacts(true)} className="lg:hidden p-2 hover:bg-slate-100 rounded-xl transition-all">
                                <ChevronLeft className="w-5 h-5 text-slate-500" />
                            </button>
                            <div className={`w-10 h-10 rounded-2xl flex items-center justify-center text-white font-black text-xs shadow-md ${selectedContact.role === 'STUDENT' ? 'bg-gradient-to-br from-emerald-400 to-teal-500 shadow-emerald-500/20' : 'bg-gradient-to-br from-indigo-400 to-purple-500 shadow-indigo-500/20'}`}>
                                {selectedContact.firstName[0]}{selectedContact.lastName[0]}
                            </div>
                            <div className="flex-1">
                                <h3 className="font-black text-slate-900 text-sm">{selectedContact.firstName} {selectedContact.lastName}</h3>
                                <div className="flex items-center gap-1.5">
                                    <Circle className="w-2 h-2 text-emerald-400 fill-emerald-400" />
                                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                                        {selectedContact.role}{selectedContact.studentClass ? ` · ${selectedContact.studentClass}` : ''}
                                    </span>
                                </div>
                            </div>
                        </div>

                        {/* Messages */}
                        <div className="flex-1 overflow-y-auto px-6 py-6 space-y-1">
                            {groupedMessages.length > 0 ? (
                                groupedMessages.map((group, gi) => (
                                    <div key={gi}>
                                        <div className="flex justify-center my-6">
                                            <span className="px-4 py-1.5 bg-slate-200/60 rounded-full text-[10px] font-black text-slate-400 uppercase tracking-widest">{group.date}</span>
                                        </div>
                                        {group.msgs.map((msg) => {
                                            const isMine = msg.senderId === currentUserId;
                                            return (
                                                <div key={msg.id} className={`flex mb-3 ${isMine ? 'justify-end' : 'justify-start'}`}>
                                                    <div className={`max-w-[75%] lg:max-w-[60%] px-5 py-3 rounded-3xl shadow-sm ${
                                                        isMine
                                                            ? 'bg-indigo-600 text-white rounded-br-lg'
                                                            : 'bg-white text-slate-800 border border-slate-100 rounded-bl-lg'
                                                    }`}>
                                                        <p className="text-sm font-medium leading-relaxed whitespace-pre-wrap break-words">{msg.content}</p>
                                                        <p className={`text-[9px] font-bold mt-1.5 ${isMine ? 'text-indigo-200' : 'text-slate-300'} text-right`}>
                                                            {formatTime(msg.createdAt)}
                                                            {isMine && msg.isRead && <span className="ml-1">✓✓</span>}
                                                        </p>
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                ))
                            ) : (
                                <div className="h-full flex flex-col items-center justify-center text-center">
                                    <div className="w-20 h-20 bg-slate-100 rounded-full flex items-center justify-center mb-4">
                                        <MessageCircle className="w-8 h-8 text-slate-300" />
                                    </div>
                                    <h3 className="font-bold text-slate-500 mb-1">No messages yet</h3>
                                    <p className="text-xs text-slate-400 font-medium">Start the conversation with {selectedContact.firstName}!</p>
                                </div>
                            )}
                            <div ref={messagesEndRef} />
                        </div>

                        {/* Input Bar */}
                        <form onSubmit={handleSend} className="bg-white px-6 py-4 border-t border-slate-100 flex items-center gap-3 shrink-0">
                            <input
                                value={newMessage}
                                onChange={e => setNewMessage(e.target.value)}
                                placeholder="Type a message..."
                                className="flex-1 bg-slate-50 rounded-2xl px-6 py-3.5 text-sm font-bold outline-none focus:bg-slate-100 transition-all text-slate-800 placeholder:text-slate-300"
                            />
                            <button
                                type="submit"
                                disabled={!newMessage.trim() || sending}
                                className="w-12 h-12 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-200 text-white disabled:text-slate-400 rounded-2xl flex items-center justify-center transition-all shadow-lg shadow-indigo-500/20 disabled:shadow-none active:scale-95"
                            >
                                <Send className="w-5 h-5" />
                            </button>
                        </form>
                    </>
                ) : (
                    <div className="flex-1 flex flex-col items-center justify-center text-center px-8">
                        <div className="w-28 h-28 bg-slate-100 rounded-full flex items-center justify-center mb-6">
                            <MessageCircle className="w-12 h-12 text-slate-250" />
                        </div>
                        <h2 className="text-2xl font-black text-slate-800 mb-2">Teacher Messages</h2>
                        <p className="text-sm text-slate-400 font-medium max-w-sm">Select a student or colleague from the contacts panel to start a conversation.</p>
                    </div>
                )}
            </div>
        </div>
    );
}
