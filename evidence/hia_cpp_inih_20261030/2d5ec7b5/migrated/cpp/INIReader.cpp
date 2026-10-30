// Read an INI file into easy-to-access name/value pairs.

// SPDX-License-Identifier: BSD-3-Clause

// Copyright (C) 2009-2025, Ben Hoyt

// inih and INIReader are released under the New BSD license (see LICENSE.txt).
// Go to the project home page for more info:
//
// https://github.com/benhoyt/inih

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include "../ini.h"
#include "INIReader.h"
#include "inih_hepta_callback.hpp"

using std::string;

INIReader::INIReader(const string& filename)
{
    hepta_ini::ScopedBorrow borrow(this);

    _error = ini_parse(filename.c_str(), ValueHandler, borrow.user());
    borrow.rethrow_pending();
}

INIReader::INIReader(const char *buffer, size_t buffer_size)
{
    hepta_ini::ScopedBorrow borrow(this);

  _error = ini_parse_string_length(buffer, buffer_size, ValueHandler, borrow.user());
    borrow.rethrow_pending();
}

int INIReader::ParseError() const
{
    return _error;
}

string INIReader::ParseErrorMessage() const
{
    switch (hia_ini_error_kind(_error)) {
    case 1: return "parse error on line " + std::to_string(_error) + "; missing ']' or '='?";
    case 2: return "unable to read file";
    case 3: return "unable to allocate memory";
    case 4: return "unable to open file";
    case 5: return "";
    default: return "unknown error " + std::to_string(_error);
    }
}

string INIReader::Get(const string& section, const string& name, const string& default_value) const
{
    string key = MakeKey(section, name);
    // Use _values.find() here instead of _values.at() to support pre C++11 compilers
    return _values.count(key) ? _values.find(key)->second : default_value;
}

string INIReader::GetString(const string& section, const string& name, const string& default_value) const
{
    const string str = Get(section, name, "");
    return str.empty() ? default_value : str;
}

long INIReader::GetInteger(const string& section, const string& name, long default_value) const
{
    string valstr = Get(section, name, "");
    const char* value = valstr.c_str();
    char* end;
    // This parses "1234" (decimal) and also "0x4D2" (hex)
    long n = strtol(value, &end, 0);
    return end > value ? n : default_value;
}

INI_API int64_t INIReader::GetInteger64(const string& section, const string& name, int64_t default_value) const
{
    string valstr = Get(section, name, "");
    const char* value = valstr.c_str();
    char* end;
    // This parses "1234" (decimal) and also "0x4D2" (hex)
    int64_t n = strtoll(value, &end, 0);
    return end > value ? n : default_value;
}

unsigned long INIReader::GetUnsigned(const string& section, const string& name, unsigned long default_value) const
{
    string valstr = Get(section, name, "");
    const char* value = valstr.c_str();
    char* end;
    // This parses "1234" (decimal) and also "0x4D2" (hex)
    unsigned long n = strtoul(value, &end, 0);
    return end > value ? n : default_value;
}

INI_API uint64_t INIReader::GetUnsigned64(const string& section, const string& name, uint64_t default_value) const
{
    string valstr = Get(section, name, "");
    const char* value = valstr.c_str();
    char* end;
    // This parses "1234" (decimal) and also "0x4D2" (hex)
    uint64_t n = strtoull(value, &end, 0);
    return end > value ? n : default_value;
}

double INIReader::GetReal(const string& section, const string& name, double default_value) const
{
    string valstr = Get(section, name, "");
    const char* value = valstr.c_str();
    char* end;
    double n = strtod(value, &end);
    return end > value ? n : default_value;
}

bool INIReader::GetBoolean(const string& section, const string& name, bool default_value) const
{
    string valstr = Get(section, name, "");
    // Convert to lower case to make string comparisons case-insensitive
    std::transform(valstr.begin(), valstr.end(), valstr.begin(),
        [](const unsigned char& ch) { return static_cast<unsigned char>(::tolower(ch)); });
        uint32_t state = 0;
    for (unsigned char ch : valstr) {
        state = hia_ini_bool_step(state, static_cast<uint32_t>(ch));
    }
    return hia_ini_bool_finish(state, default_value ? 1U : 0U) != 0;
}

std::vector<string> INIReader::Sections() const
{
    std::set<string> sectionSet;
    for (std::map<string, string>::const_iterator it = _values.begin(); it != _values.end(); ++it) {
        size_t pos = it->first.find('=');
        if (pos != string::npos) {
            sectionSet.insert(it->first.substr(0, pos));
        }
    }
    return std::vector<string>(sectionSet.begin(), sectionSet.end());
}

std::vector<string> INIReader::Keys(const string& section) const
{
    std::vector<string> keys;
    string keyPrefix = MakeKey(section, "");
    for (std::map<string, string>::const_iterator it = _values.begin(); it != _values.end(); ++it) {
        if (it->first.compare(0, keyPrefix.length(), keyPrefix) == 0) {
            keys.push_back(it->first.substr(keyPrefix.length()));
        }
    }
    return keys;
}

bool INIReader::HasSection(const string& section) const
{
    const string key = MakeKey(section, "");
    std::map<string, string>::const_iterator pos = _values.lower_bound(key);
    if (pos == _values.end())
        return false;
    // Does the key at the lower_bound pos start with "section"?
    return pos->first.compare(0, key.length(), key) == 0;
}

bool INIReader::HasValue(const string& section, const string& name) const
{
    string key = MakeKey(section, name);
    return _values.count(key);
}

string INIReader::MakeKey(const string& section, const string& name)
{
    string key = section + "=" + name;
    // Convert to lower case to make section/name lookups case-insensitive
    std::transform(key.begin(), key.end(), key.begin(),
        [](const unsigned char& ch) { return static_cast<unsigned char>(::tolower(ch)); });
    return key;
}

int INIReader::ValueHandler(void* user, const char* section, const char* name,
                            const char* value)
{
    hepta_ini::CallbackInvocation callback(user);
    if (!callback) { return 0; }
    try {
        if (hia_ini_callback_action(name ? 1U : 0U, 0, 0) == 0) { return 1; }
        INIReader* reader = static_cast<INIReader*>(callback.owner());
        string key = MakeKey(section, name);
        uint32_t action = hia_ini_callback_action(1, value ? 1U : 0U,
                                                 reader->_values[key].size() > 0 ? 1U : 0U);
        if (action == 3 || action == 4) { reader->_values[key] += "\n"; }
        reader->_values[key] += (action == 2 || action == 4) ? value : "";
        return 1;
    } catch (...) {
        callback.capture_failure();
        return 0;
    }
}
