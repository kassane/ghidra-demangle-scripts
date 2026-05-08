import Foundation

protocol Validatable {
    func validate(key: String) -> Result<Void, ValidationError>
}

enum ValidationError: Error, CustomStringConvertible {
    case wrongLength(got: Int, expected: Int)
    case checksumMismatch(got: Int, expected: Int)
    case wrongPrefix(got: Character, expected: Character)

    var description: String {
        switch self {
        case .wrongLength(let g, let e):      return "key length \(g), expected \(e)"
        case .checksumMismatch(let g, let e): return "checksum \(g), expected \(e)"
        case .wrongPrefix(let g, let e):      return "prefix '\(g)', expected '\(e)'"
        }
    }
}

// Generic struct — monomorphization produces distinct $s symbols per concrete type
struct DataProcessor<T: Numeric & CVarArg> {
    var data: [T]

    mutating func transform(multiplier: T, offset: T) {
        data = data.map { $0 * multiplier + offset }
    }
}

struct License {
    let key: String
    static let requiredLength   = 12
    static let requiredChecksum = 0x4B2

    func isValid() -> Result<Void, ValidationError> {
        guard key.count == Self.requiredLength else {
            return .failure(.wrongLength(got: key.count, expected: Self.requiredLength))
        }
        let sum = key.unicodeScalars.reduce(0) { $0 + Int($1.value) }
        guard sum == Self.requiredChecksum else {
            return .failure(.checksumMismatch(got: sum, expected: Self.requiredChecksum))
        }
        return .success(())
    }
}

final class LicenseValidator: Validatable {
    let name: String
    let requiredPrefix: Character

    init(name: String, requiredPrefix: Character) {
        self.name = name
        self.requiredPrefix = requiredPrefix
    }

    func validate(key: String) -> Result<Void, ValidationError> {
        guard key.first == requiredPrefix else {
            return .failure(.wrongPrefix(got: key.first ?? "?", expected: requiredPrefix))
        }
        return License(key: key).isValid()
    }
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    fputs("Usage: \(args[0]) <license_key>\n", stderr)
    exit(1)
}

let validator = LicenseValidator(name: "ProdValidator", requiredPrefix: "A")

switch validator.validate(key: args[1]) {
case .success:
    print("Valid license!")
case .failure(let e):
    fputs("Invalid license: \(e)\n", stderr)
    exit(1)
}

var proc = DataProcessor(data: [1, 2, 3, 4, 5] as [Int32])
proc.transform(multiplier: 2, offset: 0xDEAD)
print("Processed: \(proc.data[0]) \(proc.data[1]) \(proc.data[2])")
