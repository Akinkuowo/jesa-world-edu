"use client";

import { useState, useEffect } from "react";
import { X, Calculator, Minimize2, Maximize2, RotateCcw } from "lucide-react";

export default function ScientificCalculator({ onClose }: { onClose: () => void }) {
    const [display, setDisplay] = useState("0");
    const [memory, setMemory] = useState(0);
    const [history, setHistory] = useState("");

    const handleNumber = (n: string) => {
        if (display === "0") setDisplay(n);
        else setDisplay(display + n);
    };

    const handleOperator = (op: string) => {
        if (display.endsWith(" ") || display === "0") return;
        setDisplay(display + " " + op + " ");
    };

    const clear = () => {
        setDisplay("0");
        setHistory("");
    };

    const backspace = () => {
        if (display.length === 1) setDisplay("0");
        else setDisplay(display.slice(0, -1).trim());
    };

    const calculate = () => {
        try {
            // Very basic parser for demonstration. For a production app, use a library or a more robust parser.
            // We'll replace the display symbols with JS evaluatable math
            let expression = display
                .replace(/×/g, "*")
                .replace(/÷/g, "/")
                .replace(/π/g, Math.PI.toString())
                .replace(/e/g, Math.E.toString());
            
            // Handle scientific functions (simple regex replacement for this mockup)
            // In a real app, you'd use a math parser like mathjs
            const result = eval(expression);
            setHistory(display + " =");
            setDisplay(Number.isInteger(result) ? result.toString() : result.toFixed(8).replace(/\.?0+$/, ""));
        } catch (error) {
            setDisplay("Error");
        }
    };

    const handleScientific = (func: string) => {
        try {
            const val = parseFloat(display);
            let result = 0;
            switch(func) {
                case 'sin': result = Math.sin(val * Math.PI / 180); break;
                case 'cos': result = Math.cos(val * Math.PI / 180); break;
                case 'tan': result = Math.tan(val * Math.PI / 180); break;
                case 'sqrt': result = Math.sqrt(val); break;
                case 'log': result = Math.log10(val); break;
                case 'ln': result = Math.log(val); break;
                case 'square': result = val * val; break;
                default: return;
            }
            setHistory(`${func}(${val}) =`);
            setDisplay(result.toFixed(8).replace(/\.?0+$/, ""));
        } catch (e) {
            setDisplay("Error");
        }
    };

    return (
        <div className="fixed bottom-24 right-8 w-80 bg-slate-900/95 backdrop-blur-2xl border border-white/10 rounded-[2rem] shadow-2xl z-[100] flex flex-col overflow-hidden animate-in slide-in-from-bottom-5 duration-300">
            {/* Header */}
            <div className="bg-white/5 p-5 flex items-center justify-between border-b border-white/5">
                <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-indigo-500 rounded-lg flex items-center justify-center shadow-lg shadow-indigo-500/20">
                        <Calculator className="w-4 h-4 text-white" />
                    </div>
                    <div>
                        <h4 className="text-white text-xs font-black uppercase tracking-widest">Scientific</h4>
                        <p className="text-[10px] text-slate-400 font-bold">Calculator Pro</p>
                    </div>
                </div>
                <button 
                    onClick={onClose}
                    className="p-2 hover:bg-white/10 rounded-xl transition-colors text-slate-400 hover:text-white"
                >
                    <X className="w-5 h-5" />
                </button>
            </div>

            {/* Display */}
            <div className="p-6 bg-slate-950/50 flex flex-col items-end justify-end space-y-1 min-h-[120px]">
                <div className="text-slate-500 text-xs font-bold tracking-tight h-4">{history}</div>
                <div className="text-white text-4xl font-light tracking-tighter truncate w-full text-right overflow-x-auto scrollbar-hide">
                    {display}
                </div>
            </div>

            {/* Keys */}
            <div className="p-4 grid grid-cols-4 gap-2">
                {/* Scientific Row */}
                <button onClick={() => handleScientific('sin')} className="h-10 flex items-center justify-center bg-white/5 hover:bg-white/10 text-slate-400 rounded-lg font-bold transition-all active:scale-95 text-[10px] uppercase tracking-widest">sin</button>
                <button onClick={() => handleScientific('cos')} className="h-10 flex items-center justify-center bg-white/5 hover:bg-white/10 text-slate-400 rounded-lg font-bold transition-all active:scale-95 text-[10px] uppercase tracking-widest">cos</button>
                <button onClick={() => handleScientific('tan')} className="h-10 flex items-center justify-center bg-white/5 hover:bg-white/10 text-slate-400 rounded-lg font-bold transition-all active:scale-95 text-[10px] uppercase tracking-widest">tan</button>
                <button onClick={clear} className="h-10 flex items-center justify-center bg-white/5 hover:bg-white/10 text-rose-400 rounded-lg font-bold transition-all active:scale-95 text-xs">AC</button>

                <button onClick={() => handleScientific('log')} className="h-10 flex items-center justify-center bg-white/5 hover:bg-white/10 text-slate-400 rounded-lg font-bold transition-all active:scale-95 text-[10px] uppercase tracking-widest">log</button>
                <button onClick={() => handleScientific('ln')} className="h-10 flex items-center justify-center bg-white/5 hover:bg-white/10 text-slate-400 rounded-lg font-bold transition-all active:scale-95 text-[10px] uppercase tracking-widest">ln</button>
                <button onClick={() => handleScientific('sqrt')} className="h-10 flex items-center justify-center bg-white/5 hover:bg-white/10 text-slate-400 rounded-lg font-bold transition-all active:scale-95 text-[10px] uppercase tracking-widest">√</button>
                <button onClick={backspace} className="h-10 flex items-center justify-center bg-white/5 hover:bg-white/10 text-slate-300 rounded-lg font-bold transition-all active:scale-95 text-xs">⌫</button>

                {/* Main Pad */}
                <button onClick={() => handleNumber('7')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">7</button>
                <button onClick={() => handleNumber('8')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">8</button>
                <button onClick={() => handleNumber('9')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">9</button>
                <button onClick={() => handleOperator('/')} className="h-12 flex items-center justify-center bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 rounded-xl font-bold transition-all active:scale-95 text-xl">÷</button>

                <button onClick={() => handleNumber('4')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">4</button>
                <button onClick={() => handleNumber('5')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">5</button>
                <button onClick={() => handleNumber('6')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">6</button>
                <button onClick={() => handleOperator('*')} className="h-12 flex items-center justify-center bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 rounded-xl font-bold transition-all active:scale-95 text-xl">×</button>

                <button onClick={() => handleNumber('1')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">1</button>
                <button onClick={() => handleNumber('2')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">2</button>
                <button onClick={() => handleNumber('3')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">3</button>
                <button onClick={() => handleOperator('-')} className="h-12 flex items-center justify-center bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 rounded-xl font-bold transition-all active:scale-95 text-xl">−</button>

                <button onClick={() => handleNumber('0')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">0</button>
                <button onClick={() => handleNumber('.')} className="h-12 flex items-center justify-center bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all active:scale-95 text-lg">.</button>
                <button onClick={calculate} className="col-span-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-black text-lg transition-all active:scale-95 shadow-lg shadow-indigo-600/20">=</button>
                
                <button onClick={() => handleOperator('+')} className="h-12 flex items-center justify-center bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 rounded-xl font-bold transition-all active:scale-95 text-xl col-start-4 row-start-6">+</button>
            </div>
        </div>
    );
}
