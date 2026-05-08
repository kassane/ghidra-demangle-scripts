module target;

import std.stdio  : writeln, writefln;
import std.string : toStringz;

// ── extern(D) — _D* mangled symbols ──────────────────────────────────────────

struct License {
    string key;

    // std.algorithm.fold is not nothrow; manual loop satisfies nothrow @nogc
    bool isValid() const @safe pure nothrow @nogc scope {
        if (key.length != 12) return false;
        int sum = 0;
        foreach (c; key) sum += cast(int) c;
        return sum == 0x4B2;
    }
}

void processData(ref int[] arr) @safe pure nothrow @nogc {
    foreach (ref x; arr) {
        x = x * 2 + 0xDEAD;
    }
}

// @trusted bridge: converts C++-compatible types back to D types for isValid()
private bool validateBridge(const(char)* key, size_t len)
    @trusted pure nothrow @nogc
{
    return License(cast(immutable(char)[]) key[0 .. len]).isValid();
}

// ── extern(C++, "security") — _ZN8security* mangled symbols ──────────────────
// Block form keeps this namespace independent of the crackme block below.
extern(C++, "security") {
    // @trusted: pointer arithmetic for C++ ABI interop
    uint fnv1a(const(char)* data, size_t len) @trusted nothrow @nogc {
        uint h = 0x811c9dc5u;
        foreach (i; 0 .. len) {
            h ^= cast(uint) data[i];
            h *= 0x01000193u;
        }
        return h;
    }
}

// ── extern(C++, "crackme") — _ZN7crackme* mangled symbols ────────────────────
// D slices (string, int[]) have no C++ ABI — use const(char)* + size_t instead.
extern(D):
extern(C++, "crackme") {
    class Validator {
        private const(char)* _name;

        this(const(char)* name) {
            _name = name;
        }

        bool validate(const(char)* key, size_t len) {
            return validateBridge(key, len);
        }

        const(char)* name() const { return _name; }

        ~this() {}
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(string[] args) {
    if (args.length < 2) {
        writefln("Usage: %s <license_key>", args[0]);
        return 1;
    }

    auto v = new Validator(args[0].toStringz);

    if (!v.validate(&args[1][0], args[1].length)) {
        writeln("Invalid license.");
        return 1;
    }
    writeln("Valid license!");

    int[] data = [1, 2, 3, 4, 5];
    processData(data);
    writefln("Processed: %d %d %d", data[0], data[1], data[2]);

    uint h = fnv1a(&args[1][0], args[1].length);
    writefln("FNV-1a: 0x%08x", h);
    return 0;
}
