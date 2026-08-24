#ifndef COLORS_HPP
#define COLORS_HPP

#include <string_view>

namespace Color {
    // Reset / Modifiers
    inline constexpr std::string_view Reset       = "\033[0m";
    inline constexpr std::string_view Bold        = "\033[1m";
    inline constexpr std::string_view Dim         = "\033[2m";

    // Standard 16-Color Set
    inline constexpr std::string_view Red         = "\033[31m";
    inline constexpr std::string_view Green       = "\033[32m";
    inline constexpr std::string_view Yellow      = "\033[33m";
    inline constexpr std::string_view Blue        = "\033[34m";
    inline constexpr std::string_view Magenta     = "\033[35m";
    inline constexpr std::string_view Cyan        = "\033[36m";
    inline constexpr std::string_view White       = "\033[37m";
    inline constexpr std::string_view Gray        = "\033[90m";

    // Bright / Bold Variants
    inline constexpr std::string_view BoldRed     = "\033[1;31m";
    inline constexpr std::string_view BoldGreen   = "\033[1;32m";
    inline constexpr std::string_view BoldYellow  = "\033[1;33m";
    inline constexpr std::string_view BoldCyan    = "\033[1;36m";
    inline constexpr std::string_view BoldWhite   = "\033[1;37m";

    // VT100 Control Sequences
    inline constexpr std::string_view ClearLine   = "\033[K";
}

#endif // COLORS_HPP
