#pragma once
#include <string>
#include <filesystem>

#ifdef _WIN32
# include <Windows.h>
#endif

namespace xtls {

inline std::string pathToString(const std::filesystem::path& path) {
#ifdef _WIN32
    auto& wstr = path.native();
    int count = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.length(), NULL, 0, NULL, NULL);
    std::string str(count, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], count, NULL, NULL);
    return str;
#else
    return path.string();
#endif
}

}