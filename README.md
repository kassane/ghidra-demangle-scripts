# Ghidra Headless RE: C++23, D, Rust, Swift

Headless Ghidra toolkit — demangle symbols, rename functions, and decompile binaries for four languages without opening the GUI.

## Requirements

| Tool | Notes |
|------|-------|
| Ghidra | `analyzeHeadless` at `/opt/ghidra/support/` |
| g++ 13+ | `-std=c++23` support |
| LDC2 | includes `ddemangle` |
| c++filt | GNU binutils, standard on Linux |
| rustfilt | `cargo install rustfilt` |
| swift-demangle | Swift toolchain, must be on `PATH` |

## Layout

```
ghidra-demangle-scripts/
├── decompile.sh                        # build all samples + run all Ghidra passes
├── sample/
│   ├── target.cpp / target_cpp         # C++23
│   ├── target.d   / target_d           # D (extern(D) + extern(C++, "ns"))
│   ├── target.rs  / target_rust        # Rust
│   └── target.swift / target_swift     # Swift
├── ghidra_scripts/
│   ├── ExtractFunctions.java   # C++23 feature tagging + xrefs + decompile
│   ├── DemangleD.java          # _D* via ddemangle, _Z* via c++filt
│   ├── DemangleRust.java       # _R* and _ZN*…h<hash>E via rustfilt
│   └── DemangleSwift.java      # $s / _$s via swift-demangle
├── *_analysis_output.txt               # generated: symbol + function reports
└── *_decompiled_output.c               # generated: Ghidra decompiler output
```

## Build Samples & Run Analysis

```bash
bash decompile.sh
```

The script builds all four sample binaries and runs each Ghidra headless pass in sequence. Output files are written to the repo root:

| File | Script |
|------|--------|
| `cpp_analysis_output.txt` | `ExtractFunctions.java` |
| `cpp_decompiled_output.c` | `ExtractFunctions.java` |
| `d_analysis_output.txt` | `DemangleD.java` |
| `d_decompiled_output.c` | `DemangleD.java` |
| `rust_analysis_output.txt` | `DemangleRust.java` |
| `rust_decompiled_output.c` | `DemangleRust.java` |
| `swift_analysis_output.txt` | `DemangleSwift.java` |
| `swift_decompiled_output.c` | `DemangleSwift.java` |

Override output paths per-pass with `-scriptArgs "output.path=/tmp/out.txt decompile.path=/tmp/out.c"`.

All four samples share the same license logic: length 12, byte/scalar sum `0x4B2`, prefix `A`.
Valid key example: `Auffffffffff`.

## Scripts

### ExtractFunctions.java — C++23

Tags functions with detected C++23 features and decompiles all non-thunk functions to `cpp_decompiled_output.c`. Ghidra's built-in demangler strips `std::` before postScripts run, so the script scans the full signature string (name + param types + return type) and matches bare forms:

| Tag | Matches |
|-----|---------|
| `[C++23:expected]` | `expected<` |
| `[C++23:print]` | `println`, `vprint_*` |
| `[C++23:fold]` | `fold_left`, `fold_right` |
| `[C++23:deducing-this]` | `(this ` in signature |
| `[C++23:flat]` | `flat_map`, `flat_set` |
| `[C++23:generator]` | `generator<` |

### DemangleD.java — D

- `_D*` → `ddemangle` via **stdin** (passing as CLI arg causes "Cannot open file")
- `_Z*` → `c++filt <symbol>`
- Reports `[extern(D)  ]` / `[extern(C++)]` per symbol
- Auto-discovers `ddemangle` from `PATH` then `~/.dlang/*/bin/`

### DemangleRust.java — Rust

- `_R*` → v0 mangling
- `_ZN*17h[0-9a-f]{16}E` → legacy mangling (hash suffix distinguishes Rust from C++)
- Both handled by `rustfilt <symbol>`; auto-discovers from `PATH` then `~/.cargo/bin/`

### DemangleSwift.java — Swift

- `$s` prefix on Linux, `_$s` on macOS
- `swift-demangle <symbol>` outputs `mangled ---> demangled`; script splits on ` ---> `
- Auto-discovers from `PATH` then `/usr/bin/swift-demangle`

## D Namespace Gotcha

LDC2's colon-form `extern(C++, "ns"):` accumulates namespace context — a second block nests inside the first. Use **block form** instead:

```d
extern(C++, "security") { uint fnv1a(...) { ... } }   // → security::fnv1a
extern(C++, "crackme")  { class Validator { ... } }   // → crackme::Validator
```

String-literal form (`"ns"`) specifies an absolute namespace path; identifier form (`ns`) does not.

D slices (`string`, `int[]`) have no C++ ABI — use `const(char)*` + `size_t` in `extern(C++)` methods and bridge back to D logic via a `@trusted` function.

## Gotchas

| | |
|---|---|
| `ldc2 -of=~/...` | `~` not expanded; use `$HOME` or absolute path |
| `ddemangle` | stdin only — not CLI arg |
| `c++filt` / `rustfilt` | CLI arg — not stdin |
| `--edition=` | valid: 2023, 2024, 2025 |
| `-preview=safer` | disallows `.ptr` on slices; use `&arr[0]` |
| `grep '$s'` | use `-F` flag; `$s` is not a shell variable |

## References

- [Ghidra Scripting API](https://ghidra.re/online-docs/api/ghidra/app/script/GhidraScript.html)
- [DecompInterface API](https://ghidra.re/online-docs/api/ghidra/app/decompiler/DecompInterface.html)
- [D extern(C++) interop](https://dlang.org/spec/cpp_interface.html)
- [Rust symbol mangling v0](https://doc.rust-lang.org/rustc/symbol-mangling/v0.html)
- [Swift ABI mangling](https://github.com/apple/swift/blob/main/docs/ABI/Mangling.rst)
- [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling)
