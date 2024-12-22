
add_executable(utest
        catch.hpp
        runner.cpp

        io-stream.cpp
        io-file.cpp
        io-codec.cpp
        math-big-integer.cpp

        security-message-digest.cpp
        security-key.cpp
        security-cipher.cpp
        security-signature.cpp
        security-pem.cpp
)

target_link_libraries(utest cexxy_core cexxy_security)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

add_test(NAME utest COMMAND utest)
