// Ghidra headless script: demangle Swift 5+ ($s / _$s) symbols and decompile
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.*;

public class DemangleSwift extends GhidraScript {

    private static final String PROJECT   = System.getProperty("user.dir");
    private static final String SWIFT_DEM = resolveSwiftDemangle();

    private static File findOnPath(String name) {
        String path = System.getenv("PATH");
        if (path == null) return null;
        for (String dir : path.split(File.pathSeparator)) {
            File f = new File(dir, name);
            if (f.isFile() && f.canExecute()) return f;
        }
        return null;
    }

    private static String resolveSwiftDemangle() {
        File onPath = findOnPath("swift-demangle");
        if (onPath != null) return onPath.getPath();

        File system = new File("/usr/bin/swift-demangle");
        if (system.canExecute()) return system.getPath();

        return "swift-demangle";
    }

    @Override
    public void run() throws Exception {
        String reportPath = System.getProperty("output.path",
            PROJECT + "/swift_analysis_output.txt");
        String decompiledPath = System.getProperty("decompile.path",
            PROJECT + "/swift_decompiled_output.c");

        PrintWriter report   = new PrintWriter(new FileWriter(reportPath));
        PrintWriter decompOut = new PrintWriter(new FileWriter(decompiledPath));

        report.println("=== GHIDRA SWIFT ANALYSIS REPORT ===");
        report.println("Binary:   " + currentProgram.getName());
        report.println("Language: " + currentProgram.getLanguage().getLanguageID());
        report.println();

        report.println("=== DEMANGLED SWIFT SYMBOLS ===");
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator allSyms = symTable.getAllSymbols(true);

        int count = 0;
        while (allSyms.hasNext()) {
            Symbol sym = allSyms.next();
            String raw = sym.getName();

            // Linux: $s prefix; macOS: _$s prefix.
            if (!raw.startsWith("$s") && !raw.startsWith("_$s")) continue;

            String demangled = swiftDemangle(raw);
            if (demangled == null) continue;

            report.printf("  [0x%s]%n    %s%n    -> %s%n",
                sym.getAddress(), raw, demangled);
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
        decompOut.println("/* Decompiled Swift binary — " + currentProgram.getName() + " */\n");

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

        println("Swift report  -> " + reportPath);
        println("Decompiled " + decompCount + " functions -> " + decompiledPath);
    }

    // Output format: "mangled ---> demangled" — split on " ---> ".
    private String swiftDemangle(String symbol) {
        try {
            Process p = new ProcessBuilder(SWIFT_DEM, symbol)
                .redirectErrorStream(true).start();
            String r = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            if (r.isEmpty()) return null;
            int arrow = r.indexOf(" ---> ");
            if (arrow >= 0) r = r.substring(arrow + 6).trim();
            return (r.isEmpty() || r.equals(symbol)) ? null : r;
        } catch (Exception e) { return null; }
    }

    private String sanitize(String name) {
        return name.replaceAll("[^A-Za-z0-9_.]", "_").replaceAll("_+", "_");
    }
}
