#include <xtls/xtls.hpp>

using namespace geode;

namespace xtls {

TlsResult<std::shared_ptr<Context>> Backend::createContext(ContextType type) const {
    return Err(TlsError::custom("not implemented"));
}

}
