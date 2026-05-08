// Ghidra headless script: demangle Rust v0 (_R*) and legacy (_ZN*…h<hash>E) symbols, decompile
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.*;

public class DemangleRust extends GhidraScript {

    private static final String PROJECT  = System.getProperty("user.dir");
    private static final String RUSTFILT = resolveRustfilt();

    private static File findOnPath(String name) {
        String path = System.getenv("PATH");
        if (path == null) return null;
        for (String dir : path.split(File.pathSeparator)) {
            File f = new File(dir, name);
            if (f.isFile() && f.canExecute()) return f;
        }
        return null;
    }

    private static String resolveRustfilt() {
        File onPath = findOnPath("rustfilt");
        if (onPath != null) return onPath.getPath();
        File cargo = new File(System.getProperty("user.home"), ".cargo/bin/rustfilt");
        if (cargo.canExecute()) return cargo.getPath();
        return "rustfilt";
    }

    @Override
    public void run() throws Exception {
        String reportPath = System.getProperty("output.path",
            PROJECT + "/rust_analysis_output.txt");
        String decompiledPath = System.getProperty("decompile.path",
            PROJECT + "/rust_decompiled_output.c");

        PrintWriter report   = new PrintWriter(new FileWriter(reportPath));
        PrintWriter decompOut = new PrintWriter(new FileWriter(decompiledPath));

        report.println("=== GHIDRA RUST ANALYSIS REPORT ===");
        report.println("Binary:   " + currentProgram.getName());
        report.println("Language: " + currentProgram.getLanguage().getLanguageID());
        report.println();

        report.println("=== DEMANGLED RUST SYMBOLS ===");
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator allSyms = symTable.getAllSymbols(true);

        int count = 0;
        while (allSyms.hasNext()) {
            Symbol sym = allSyms.next();
            String raw = sym.getName();

            // v0: _R prefix. Legacy: _ZN…17h<16 hex digits>E (hash suffix distinguishes Rust from C++).
            boolean isV0     = raw.startsWith("_R");
            boolean isLegacy = raw.startsWith("_ZN") && raw.matches(".*17h[0-9a-f]{16}E$");
            if (!isV0 && !isLegacy) continue;

            String demangled = rustfilt(raw);
            if (demangled == null) continue;

            report.printf("  [%s] [0x%s]%n    %s%n    -> %s%n",
                isV0 ? "v0 " : "leg", sym.getAddress(), raw, demangled);
            count++;

            try {
                sym.setName(sanitize(demangled), SourceType.ANALYSIS);
            } catch (Exception e) { /* skip on name collision */ }
        }
        report.println();
        report.printf("  Total demangled: %d%n", count);
        report.println();

        report.println("=== FUNCTIONS (after demangling) ===");
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);
        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (f.isExternal() || f.isThunk()) continue;
            report.printf("[0x%s] %s  (%d bytes)%n",
                f.getEntryPoint(), f.getName(), f.getBody().getNumAddresses());
        }
        report.println("=== DONE ===");
        report.close();

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        decompOut.println("/* Decompiled Rust binary — " + currentProgram.getName() + " */\n");

        funcs = fm.getFunctions(true);
        int decompCount = 0;
        while (funcs.hasNext()) {
            Function f = funcs.next();
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

        println("Rust report   -> " + reportPath);
        println("Decompiled " + decompCount + " functions -> " + decompiledPath);
    }

    private String rustfilt(String symbol) {
        try {
            Process p = new ProcessBuilder(RUSTFILT, symbol)
                .redirectErrorStream(true).start();
            String r = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return (r.isEmpty() || r.equals(symbol)) ? null : r;
        } catch (Exception e) { return null; }
    }

    private String sanitize(String name) {
        return name.replaceAll("[^A-Za-z0-9_.]", "_").replaceAll("_+", "_");
    }
}
