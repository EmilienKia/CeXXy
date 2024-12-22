
add_library(cexxy_core SHARED
        io/codec.hpp
        io/codec.cpp
        io/exceptions.hpp
        io/exceptions.cpp
        io/file.hpp
        io/file.cpp
        io/reader.hpp
        io/reader.cpp
        io/stream.hpp
        io/stream.cpp
        math/big-integer.hpp
        math/big-integer.cpp
)

target_link_libraries(cexxy_core PkgConfig::GMP)

add_library(cexxy_security SHARED
        security/exceptions.hpp
        security/exceptions.cpp
        security/crypto.hpp
        security/crypto.cpp
        security/openssl.hpp
        security/openssl.cpp
)

target_link_libraries(cexxy_security cexxy_core PkgConfig::LIBCRYPTO)