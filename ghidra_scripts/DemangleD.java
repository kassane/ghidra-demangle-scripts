// Ghidra headless script: demangle D (_D*) and extern(C++) (_Z*) symbols, decompile
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

import java.io.*;
import java.util.*;

public class DemangleD extends GhidraScript {

    private static final String PROJECT   = System.getProperty("user.dir");
    private static final String DDEMANGLE = resolveDdemangle();

    private static File findOnPath(String name) {
        String path = System.getenv("PATH");
        if (path == null) return null;
        for (String dir : path.split(File.pathSeparator)) {
            File f = new File(dir, name);
            if (f.isFile() && f.canExecute()) return f;
        }
        return null;
    }

    private static String resolveDdemangle() {
        File onPath = findOnPath("ddemangle");
        if (onPath != null) return onPath.getPath();

        // LDC2 bundles ddemangle under ~/.dlang/<ver>/<ver>-linux-x86_64/bin/
        File dlang = new File(System.getProperty("user.home"), ".dlang");
        if (dlang.isDirectory()) {
            File[] vers = dlang.listFiles();
            if (vers != null) for (File ver : vers) {
                File candidate = new File(ver,
                    ver.getName() + "-linux-x86_64/bin/ddemangle");
                if (candidate.canExecute()) return candidate.getAbsolutePath();
            }
        }
        return "ddemangle";
    }

    @Override
    public void run() throws Exception {
        String reportPath = System.getProperty("output.path",
            PROJECT + "/d_analysis_output.txt");
        String decompiledPath = System.getProperty("decompile.path",
            PROJECT + "/d_decompiled_output.c");

        PrintWriter report   = new PrintWriter(new FileWriter(reportPath));
        PrintWriter decompOut = new PrintWriter(new FileWriter(decompiledPath));

        report.println("=== GHIDRA D LANGUAGE ANALYSIS REPORT ===");
        report.println("Binary:   " + currentProgram.getName());
        report.println("Language: " + currentProgram.getLanguage().getLanguageID());
        report.println();

        report.println("=== DEMANGLED SYMBOLS ===");
        report.println("  Linkage      Mangled -> Demangled");
        report.println("  ─────────────────────────────────────────────────────");

        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator allSyms = symTable.getAllSymbols(true);

        int dCount = 0, cxxCount = 0;

        while (allSyms.hasNext()) {
            Symbol sym = allSyms.next();
            String raw = sym.getName();

            String demangled, linkage;
            if (raw.startsWith("_D")) {
                demangled = ddemangle(raw);
                linkage   = "extern(D)  ";
            } else if (raw.startsWith("_Z")) {
                demangled = cxxfilt(raw);
                linkage   = "extern(C++)";
            } else continue;

            if (demangled == null) continue;

            report.printf("  [%s] [0x%s]%n    %s%n    -> %s%n",
                linkage, sym.getAddress(), raw, demangled);

            if (raw.startsWith("_D")) dCount++;
            else                      cxxCount++;

            try {
                sym.setName(sanitize(demangled), SourceType.ANALYSIS);
            } catch (Exception e) { /* skip on name collision */ }
        }

        report.println();
        report.printf("  Totals: extern(D)=%d  extern(C++)=%d%n", dCount, cxxCount);
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
        report.println();
        report.println("=== DONE ===");
        report.close();

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        decompOut.println("/* Decompiled D binary — " + currentProgram.getName() + " */\n");

        funcs = fm.getFunctions(true);
        int count = 0;
        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (f.isExternal() || f.isThunk()) continue;
            DecompileResults res = di.decompileFunction(f, 30, monitor);
            if (res.decompileCompleted()) {
                decompOut.println("/* --- " + f.getName()
                    + " @ 0x" + f.getEntryPoint() + " --- */");
                decompOut.println(res.getDecompiledFunction().getC());
                count++;
            }
        }
        di.dispose();
        decompOut.close();

        println("D report      -> " + reportPath);
        println("Decompiled " + count + " functions -> " + decompiledPath);
    }

    // ddemangle reads from stdin, not CLI args — passing as arg causes "Cannot open file".
    private String ddemangle(String symbol) {
        try {
            Process p = new ProcessBuilder(DDEMANGLE)
                .redirectErrorStream(true).start();
            p.getOutputStream().write((symbol + "\n").getBytes());
            p.getOutputStream().close();
            String r = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return (r.isEmpty() || r.equals(symbol)) ? null : r;
        } catch (Exception e) { return null; }
    }

    private String cxxfilt(String symbol) {
        try {
            Process p = new ProcessBuilder("c++filt", symbol)
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
