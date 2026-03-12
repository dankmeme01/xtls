#include <xtls/Base.hpp>
#include <xtls/Backend.hpp>

namespace xtls {

#define $xerr(name, code, desc) const TlsError TlsError::name{XTLS_CODE_BASE + code, desc};

$xerr(NOT_IMPLEMENTED, 1, "Not implemented");
$xerr(WANT_READ, 2, "Operation would block on read");
$xerr(WANT_WRITE, 3, "Operation would block on write");

#undef $xerr

TlsError TlsError::lastError(int code) {
    return Backend::get().lastError(code);
}

}