// Ghidra headless script: extract functions, strings, and xrefs (C++23 aware)
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;

import java.io.*;

public class ExtractFunctions extends GhidraScript {

    private static final String PROJECT = System.getProperty("user.dir");

    @Override
    public void run() throws Exception {
        String outputPath = System.getProperty("output.path",
            PROJECT + "/cpp_analysis_output.txt");

        PrintWriter out = new PrintWriter(new FileWriter(outputPath));

        out.println("=== GHIDRA C++23 ANALYSIS REPORT ===");
        out.println("Binary:   " + currentProgram.getName());
        out.println("Language: " + currentProgram.getLanguage().getLanguageID());
        out.println("Compiler: " + currentProgram.getCompilerSpec().getCompilerSpecID());
        out.println("Base:     " + currentProgram.getImageBase());
        out.println();

        out.println("=== FUNCTIONS (demangled) ===");
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);

        while (funcs.hasNext()) {
            Function f = funcs.next();
            String raw     = f.getName();
            String display = raw.startsWith("_Z") ? cxxfilt(raw) : raw;

            // Scan full sig (name + param types + return): Ghidra strips "std::"
            // so features in type args are only visible in the concatenated string.
            StringBuilder sig = new StringBuilder(display);
            sig.append(" ").append(f.getReturnType().getName());
            for (Parameter p : f.getParameters())
                sig.append(" ").append(p.getDataType().getName());
            String tag = classifyCxx23(sig.toString());

            out.printf("[0x%s] %s%s  (%d bytes, %d params)%n",
                f.getEntryPoint(), display, tag,
                f.getBody().getNumAddresses(),
                f.getParameterCount());

            for (Parameter p : f.getParameters())
                out.printf("    param: %s %s%n", p.getDataType().getName(), p.getName());
            out.printf("    return: %s%n", f.getReturnType().getName());
        }
        out.println();

        out.println("=== DEFINED STRINGS ===");
        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);
        while (dataIt.hasNext()) {
            Data d = dataIt.next();
            if (d.hasStringValue()) {
                String val = d.getDefaultValueRepresentation();
                if (val != null && val.length() > 3)
                    out.printf("[0x%s] %s%n", d.getAddress(), val);
            }
        }
        out.println();

        out.println("=== CROSS-REFERENCES ===");
        String[] targets = {"validate", "transform", "printf", "puts",
                            "strcmp", "strcpy", "system", "exec"};
        SymbolTable symTable = currentProgram.getSymbolTable();

        for (String target : targets) {
            SymbolIterator syms = symTable.getSymbols(target);
            while (syms.hasNext()) {
                Symbol sym = syms.next();
                ReferenceIterator refs = currentProgram.getReferenceManager()
                    .getReferencesTo(sym.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    out.printf("  %s <- 0x%s%n", target, ref.getFromAddress());
                }
            }
        }

        out.println();
        out.println("=== DONE ===");
        out.close();
        println("Report -> " + outputPath);

        String decompiledPath = System.getProperty("decompile.path",
            PROJECT + "/cpp_decompiled_output.c");
        PrintWriter decompOut = new PrintWriter(new FileWriter(decompiledPath));
        decompOut.println("/* Decompiled C++23 binary — " + currentProgram.getName() + " */\n");

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        int decompCount = 0;
        FunctionIterator decompFuncs = currentProgram.getFunctionManager().getFunctions(true);
        while (decompFuncs.hasNext()) {
            Function f = decompFuncs.next();
            if (f.isExternal() || f.isThunk()) continue;
            DecompileResults res = di.decompileFunction(f, 30, monitor);
            if (res.decompileCompleted()) {
                decompOut.println("/* --- " + f.getName()
                    + " @ 0x" + f.getEntryPoint() + " --- */");
                decompOut.println(res.getDecompiledFunction().getC());
                decompCount++;
            }
        }
        di.dispose();
        decompOut.close();
        println("Decompiled " + decompCount + " functions -> " + decompiledPath);
    }

    private String cxxfilt(String symbol) {
        try {
            Process p = new ProcessBuilder("c++filt", symbol)
                .redirectErrorStream(true).start();
            String result = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return (result.isEmpty() || result.equals(symbol)) ? symbol : result;
        } catch (Exception e) {
            return symbol;
        }
    }

    // Ghidra's built-in demangler strips "std::" before postScripts run,
    // so match bare forms (e.g. "expected<" not "std::expected").
    private String classifyCxx23(String sig) {
        if (sig.contains("std::expected") || sig.contains("expected<")) return "  [C++23:expected]";
        if (sig.contains("std::print")    || sig.contains("println")
                                          || sig.contains("vprint_"))   return "  [C++23:print]";
        if (sig.contains("fold_left")     || sig.contains("fold_right")) return "  [C++23:fold]";
        if (sig.contains("(this ")        || sig.contains(" this,"))     return "  [C++23:deducing-this]";
        if (sig.contains("flat_map")      || sig.contains("flat_set"))   return "  [C++23:flat]";
        if (sig.contains("generator<"))                                   return "  [C++23:generator]";
        return "";
    }
}
