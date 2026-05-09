# Technical Report: Ghidra Decompiled Output Analysis

**Binaries:** `target_cpp`, `target_d`, `target_rust`, `target_swift`  
**Tool:** Ghidra headless — `ExtractFunctions.java`, `DemangleD.java`, `DemangleRust.java`, `DemangleSwift.java`  
**Date:** 2026-05-09

---

## File Size Overview

| File | Lines | Size | Notes |
|------|------:|-----:|-------|
| `cpp_decompiled_output.c` | 24,631 | 840 KB | C++23 std library inlined |
| `d_decompiled_output.c` | 95,303 | 3.2 MB | D runtime TypeInfo stubs dominate |
| `rust_decompiled_output.c` | 77,611 | 2.6 MB | Iterator monomorphization |
| `swift_decompiled_output.c` | 2,085 | 60 KB | Only user-space functions recovered |

Swift is smallest because Ghidra only decompiled non-thunk, non-external functions; the bulk of Swift stdlib is dynamically linked and absent from the binary.

---

## 1. C++ (`cpp_decompiled_output.c`)

### Structure
Entry point at `0x00104549`. Uses a stack canary (`__stack_chk_fail`).

### Key Types
```c
unique_ptr<crackme::StrictValidator, std::default_delete<crackme::StrictValidator>> validator;
DataProcessor<int> proc;
expected<bool, std::__cxx11::basic_string<...>> result;   // C++23
```

### Main Flow (`main @ 0x00104549`)
```
argc < 2  →  println("Usage: {} <license_key>")  →  exit(1)
         else
  make_unique<crackme::StrictValidator>(...)
  StrictValidator::validate(&result, this, argv[1])
  if result  →  println("Valid license!")
               DataProcessor::transform(&proc, 2, 0xdead)
               println("Processed: {} {} {}", proc[0], proc[1], proc[2])
  else       →  println("Invalid license: {}", result.error())
```

### C++23 Features Observed
- `std::println` (replaces `std::cout`) — called with `format_string` objects
- `std::expected<bool, std::string>` — wraps validation result; `.error()` path confirmed
- `DataProcessor<int>` — class template with `transform(multiplier, offset)`

### Notes
- Ghidra correctly resolved `initializer_list<int>` for the `{1,2,3,4,5}` vector literal
- `format_string` is stored as `{ptr, len}` pair on the stack before each `println` call

---

## 2. D (`d_decompiled_output.c`)

### Structure
Entry at `target::D_main @ 0x00125dc0`. The D runtime wraps it through `_start → __libc_start_main → target::main`.

### Key Functions

#### `License::isValid @ 0x00125bb0` — cleanest of all four languages
```c
bool __thiscall target::License::isValid(License *this) {
    if ((this->key).length != 0xc) return false;
    int sum = 0;
    for (ulong i = 0; i < (this->key).length; i++)
        sum = (byte)(this->key).ptr[i] + sum;
    return sum == 0x4b2;
}
```

#### `fnv1a @ 0x00125cd0` — present but **not on the validation path**
```c
uint target::fnv1a(const_char_ *data, ulong len) {
    uint h = 0x811c9dc5;          // FNV offset basis
    for (ulong i = 0; i < len; i++)
        h = ((byte)data[i] ^ h) * 0x1000193;  // FNV prime
    return h;
}
```

#### `validateBridge @ 0x00125c90`
Thin adapter: constructs a `License{key.ptr, key.len}` on the stack and calls `isValid`.

#### `processData @ 0x00125c30`
```c
for (ulong i = 0; i < arr->length; i++)
    arr->ptr[i] = arr->ptr[i] * 2 + 0xdead;
```

### D ABI Observations
- `string__` = `{ptr: immutable_char_*, length: ulong}` — slice on the stack, no heap allocation
- `Validator` uses a vtable: `_d_allocclass` allocates the object, then `*(undefined***)this_00 = &target_Validator__vtbl`
- Bounds checking calls `_d_arraybounds_index(line, file, ...)` — D's range safety at runtime; source path `/home/kassane/ghidra-demangle-scripts/sample/target.d` is embedded in the binary

### Size Culprit
The 3.2 MB output is dominated by ~hundreds of `TypeInfo_Tuple` stubs for D runtime reflection. Every method body is:
```c
void const_..._TypeInfo_Tuple_getHash_...(void) {
    /* WARNING: Does not return */
    (*invalidInstructionException())();
}
```
These are abstract vtable slots — Ghidra decompiles them but they carry no logic.

---

## 3. Rust (`rust_decompiled_output.c`)

### Structure
Entry at `_start @ 0x00116680` → `std::rt::lang_start` → `main @ 0x00116ca0`.

### Key Functions

#### `License::is_valid @ 0x00117310` — iterator chain fully preserved
```c
bool __rustcall target_rust::License::is_valid(License *self) {
    if (core::str::len(self->key) != 0xc) return false;
    Bytes bytes = core::str::bytes(self->key);
    Map<Bytes, closure_env#0> mapped =
        Iterator::map(bytes.ptr, bytes.end_or_len);  // map(|b| b as i32)
    i32 sum = Iterator::sum(mapped);
    return sum == 0x4b2;
}

// The map closure:
i32 target_rust::is_valid::{closure#0}(closure_env#0 *_, u8 b) {
    return (i32)b;
}
```

The zero-cost abstraction is resolved: `bytes().map(|b| b as i32).sum()` decompiles to an explicit `fold` chain through `core::iter::adapters::map`.

#### `DataProcessor<i32>::transform @ 0x00116bf0`
```c
void target_rust::DataProcessor<i32>::transform<i32>(
        DataProcessor<i32> *self, i32 multiplier, i32 offset) {
    // iterates self->data, applies multiplier * x + offset
}
```
Called with `multiplier=2, offset=0xdead` — matches C++ and D.

### DWARF Quality
Rust preserves the most complete DWARF of all four languages. Original function prototypes are embedded as comments:
```
/* DWARF original prototype: bool is_valid(License * self) */
/* DWARF original prototype: DataProcessor<i32> new<i32>(Vec<i32,...> data) */
```

### Size Culprit
2.6 MB output comes from monomorphization: every generic instantiation (`fold<i32, Bytes, closure_env#0, ...>`) produces a separate concrete function. The full `fold` chain for `is_valid` alone spans ~5 function stubs.

---

## 4. Swift (`swift_decompiled_output.c`)

### Structure
Entry at `_start @ 0x00102450` → `target_swift::main @ 0x00103be0`.

### Key Functions

#### `License::requiredLength_get @ 0x001031c0` / `requiredChecksum_get @ 0x001031e0`
```c
Int *target_swift::License::requiredLength_get(...)  { return (Int *)0xc;   }
Int *target_swift::License::requiredChecksum_get(...) { return (Int *)0x4b2; }
```
Constants exposed as computed properties — Ghidra recovers them as trivial getters.

#### `License::isValid @ 0x001031f0` — most complex of the four
The Swift String ABI stores length in tagged pointer bits; Ghidra emits:
```c
_Var4 = Swift::String::get_count(SVar13);
if (_Var4 == 0xc) {
    // extract byte count from tagged pointer
    uVar10 = (ulong)((byte)((ulong)in_RSI >> 0x38) & 0xf);
    if (((ulong)in_RSI >> 0x3d & 1) == 0)
        uVar10 = (ulong)this & 0xffffffffffff;
    // iterate Unicode scalars, accumulate sum
    ...
    if (_Var4 == 0x4b2) { /* success */ }
}
```
Iterates via `_StringGuts::foreignErrorCorrectedScalar` — handles multi-byte Unicode scalars, unlike the other languages which iterate raw bytes directly.

#### `LicenseValidator::validate @ 0x001027c0`
**Swift uniquely adds a prefix check:** compares the first `Character` of the key against `requiredPrefix` (`'A'`). The other three languages do not implement this check.
```c
// Simplified logic:
firstChar = Swift::first_get(key);        // key[0]
if (firstChar != requiredPrefix) goto fail;
License::isValid(licenseFromKey);
```

#### `DataProcessor::transform @ 0x00102930`
Generic over `T`; applies `Swift::map` with a closure that multiplies and adds. The partial-apply forwarder is visible:
```c
// closure_1 in DataProcessor.transform:
lVar1 = param * (*multiplierPtr);
*result = lVar1 + (*offsetPtr);   // overflow trap on i32 overflow
```

### ARC Overhead
Every function is littered with `swift_bridgeObjectRetain` / `swift_bridgeObjectRelease` pairs. The `deinit` pair releases `name` and `requiredPrefix` string bridge objects.

### Swift ABI Specifics
- `$s` / `_$s` symbol prefix (Linux vs macOS)
- Value witnesses generated for `ValidationError` enum: `initializeWithCopy`, `assignWithCopy`, `assignWithTake`, `getEnumTagSinglePayload`, `storeEnumTagSinglePayload`
- `swift_image_constructor @ 0x00102550` registers protocol conformances, reflection metadata, and type descriptors with the Swift runtime

---

## Cross-Language Diff

### Validation Algorithm

All four implementations share the same invariants:

| Check | C++ | D | Rust | Swift |
|-------|:---:|:-:|:----:|:-----:|
| `len == 12` | ✓ | ✓ | ✓ | ✓ |
| `bytesum == 0x4b2` | ✓ | ✓ | ✓ | ✓ (Unicode scalars) |
| `key[0] == 'A'` | ✗ | ✗ | ✗ | **✓** |

Swift is the only implementation that enforces a prefix constraint, making `Auffffffffff` the canonical valid key on Swift but any 12-char key with bytesum `0x4b2` valid on the others.

### Error Handling Style

| Language | Mechanism | Notes |
|----------|-----------|-------|
| C++23 | `std::expected<bool, std::string>` | `.error()` carries the reason string |
| D | `bool` return + `writeln` | Simple, direct; error string hardcoded |
| Rust | `Result`-like (stack-allocated enum) | Compiler enforces handling |
| Swift | `Result<Void, ValidationError>` enum | `ValidationError.description` computed property |

### `DataProcessor::transform` Consistency

All four call `transform(multiplier=2, offset=0xdead)` on an `{1,2,3,4,5}` dataset. The operation is `x * 2 + 0xdead` per element. Rust and Swift add **overflow traps** (`invalidInstructionException` on overflow); C++ and D do not.

### Decompiler Output Quality

| Language | Quality | Main Issue |
|----------|---------|------------|
| C++ | Good | `std::` internals inflate output; logic is clear |
| D | Good (logic), Poor (runtime) | TypeInfo stubs are noise; `D_main` logic is clean |
| Rust | Excellent | Best DWARF; full original prototypes in comments |
| Swift | Fair | ARC calls obscure data flow; String ABI is opaque |

### Symbol Demangle Coverage

- **C++**: `c++filt` resolves `_Z*` names; Ghidra's built-in demangler strips `std::` pre-script
- **D**: `ddemangle` (stdin-only) handles `_D*`; `c++filt` covers `extern(C++)` symbols
- **Rust**: `rustfilt` handles both v0 (`_R*`) and legacy (`_ZN*…h<hex>E`) — v0 names preserve full generics
- **Swift**: `swift-demangle` recovers full type/method names including generic params and access levels

---

## Key Findings Summary

1. **Shared secret**: `len=12`, `bytesum=0x4b2`, valid example `Auffffffffff` (Swift requires `A` prefix; others accept any matching key).
2. **`fnv1a` in D** is compiled into the binary but unreachable from `D_main` — likely dead code or a helper for a future feature.
3. **Rust iterator chains** are fully visible post-monomorphization; zero-cost abstractions do not hide logic from the decompiler.
4. **Swift's Unicode-aware** byte iteration means non-ASCII characters with scalar values summing to `0x4b2` would also pass — the other three use raw `u8`/`byte` sums.
5. **Overflow safety**: Rust and Swift trap on integer overflow in `transform`; C++ and D wrap silently.
6. **Binary size vs decompiled size**: D runtime reflection stubs (TypeInfo) account for ~90% of the D output despite carrying zero application logic.
