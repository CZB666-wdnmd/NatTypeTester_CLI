#pragma once

#include <cctype>
#include <map>
#include <sstream>
#include <string>
#include <string_view>

namespace natcli {

/// Abstract base class for all NAT test implementations.
/// Each RFC test module inherits from this and implements its specific test logic.
class INatTest {
public:
    virtual ~INatTest() = default;

    /// Returns the command name (e.g. "rfc3489", "rfc5780", etc.)
    virtual std::string_view commandName() const = 0;

    /// Parse command-line options specific to this test.
    /// @param options key-value map of --option -> value
    virtual void parseArgs(const std::map<std::string, std::string>& options) = 0;

    /// Execute the test and print results to stdout.
    /// @return 0 on success, non-zero on error
    virtual int runTest() = 0;

    /// Print help/usage for this test.
    virtual void printHelp() const {}

    /// Check if JSON mode is enabled.
    bool jsonMode() const { return json_mode_; }

protected:
    bool json_mode_{false};

    /// Escape a string for JSON output.
    static std::string json_escape(const std::string& s) {
        std::ostringstream out;
        for (char c : s) {
            switch (c) {
            case '"':  out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b";  break;
            case '\f': out << "\\f";  break;
            case '\n': out << "\\n";  break;
            case '\r': out << "\\r";  break;
            case '\t': out << "\\t";  break;
            default:   out << c;      break;
            }
        }
        return out.str();
    }

    /// Convert a boolean to JSON "true" or "false".
    static std::string json_bool(bool v) { return v ? "true" : "false"; }

    /// Output a JSON key-value pair: "key": value (value already JSON-formatted).
    static std::string json_kv(const std::string& key, const std::string& value) {
        return "\"" + json_escape(key) + "\":" + value;
    }

    /// Output a JSON key-value string pair: "key": "value".
    static std::string json_kv_str(const std::string& key, const std::string& value) {
        return "\"" + json_escape(key) + "\":\"" + json_escape(value) + "\"";
    }

    /// Output a JSON key-value with a nullable bool string value.
    /// "yes"/"pass" → true, "fail"/"no" → false, "unknown"/"inconclusive" → null, otherwise string.
    static std::string json_kv_result(const std::string& key, const std::string& value) {
        std::string lower;
        for (char c : value) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lower == "pass" || lower == "yes") {
            return "\"" + json_escape(key) + "\":true";
        }
        if (lower == "fail" || lower == "no") {
            return "\"" + json_escape(key) + "\":false";
        }
        if (lower == "unknown" || lower == "inconclusive" || lower == "-") {
            return "\"" + json_escape(key) + "\":null";
        }
        return "\"" + json_escape(key) + "\":\"" + json_escape(value) + "\"";
    }
};

} // namespace natcli
