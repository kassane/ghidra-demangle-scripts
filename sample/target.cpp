#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>
#include <expected>
#include <print>
#include <memory>
#include <functional>

namespace crackme {

template<typename T>
class DataProcessor {
public:
    explicit DataProcessor(std::vector<T> data) : data_(std::move(data)) {}

    void transform(T multiplier, T offset) {
        for (auto& x : data_) x = x * multiplier + offset;
    }

    // C++23 deducing this: one overload covers const and non-const callers
    template<typename Self>
    auto& data(this Self&& self) { return self.data_; }

private:
    std::vector<T> data_;
};

class LicenseValidator {
public:
    explicit LicenseValidator(std::string name) : name_(std::move(name)) {}

    [[nodiscard]] std::expected<bool, std::string>
    validate(const std::string& key) const {
        if (key.size() != 12)
            return std::unexpected("key length must be 12");

        // fold_left is in <algorithm>, not <ranges>
        int sum = std::ranges::fold_left(key, 0, std::plus{});
        if (sum != 0x4B2)
            return std::unexpected("checksum mismatch");

        return true;
    }

    template<typename Self>
    auto& name(this Self&& self) { return self.name_; }

    virtual ~LicenseValidator() = default;

private:
    std::string name_;
};

class StrictValidator : public LicenseValidator {
public:
    explicit StrictValidator(std::string name, char required_prefix)
        : LicenseValidator(std::move(name)), prefix_(required_prefix) {}

    [[nodiscard]] std::expected<bool, std::string>
    validate(const std::string& key) const {
        if (key.empty() || key[0] != prefix_)
            return std::unexpected("key must start with required prefix");
        return LicenseValidator::validate(key);
    }

private:
    char prefix_;
};

} // namespace crackme

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::println("Usage: {} <license_key>", argv[0]);
        return 1;
    }

    auto validator = std::make_unique<crackme::StrictValidator>("ProdValidator", 'A');

    auto result = validator->validate(argv[1]);
    if (!result) {
        std::println("Invalid license: {}", result.error());
        return 1;
    }
    std::println("Valid license!");

    crackme::DataProcessor<int> proc({1, 2, 3, 4, 5});
    proc.transform(2, 0xDEAD);

    const auto& data = proc.data();
    std::println("Processed: {} {} {}", data[0], data[1], data[2]);
    return 0;
}
