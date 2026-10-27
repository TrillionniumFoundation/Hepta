#pragma once
// Authored API adaptation, counted separately from generated bridge code.
// selected.hpp must include the exact upstream json.hpp before this header.
#include <cstdint>
#include <span>
#include <stdexcept>
namespace hepta_json_upgrade {
class Document {
    nlohmann::json value_;
public:
    explicit Document(std::span<const std::uint8_t> text)
        : value_(nlohmann::json::parse(text.begin(), text.end())) {
        if (!value_.is_object() || !value_.contains("values") ||
            !value_.at("values").is_array() || value_.at("values").size() > 64)
            throw std::invalid_argument("expected up to 64 integer values");
        for (const auto& item : value_.at("values")) {
            if (!item.is_number_integer() || item < -1000000 || item > 1000000)
                throw std::invalid_argument("integer outside bounded domain");
        }
    }
    void replace(std::size_t index, std::int64_t value) {
        if (value < -1000000 || value > 1000000)
            throw std::invalid_argument("replacement outside bounded domain");
        value_.at("values").at(index) = value;
    }
    std::int64_t sum() const {
        std::int64_t result = 0;
        for (const auto& item : value_.at("values"))
            result += item.get<std::int64_t>();
        return result;
    }
};
}
