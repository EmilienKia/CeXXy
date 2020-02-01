# tests

TESTS = test-base test-security

check_PROGRAMS = $(TESTS)

test_base_SOURCES = io-stream.cpp io-file.cpp io-codec.cpp math-big-integer.cpp runner.cpp
test_base_CXXFLAGS = -I../src/
test_base_LDADD = ../src/libcexxy-core.la

test_security_SOURCES = security-message-digest.cpp security-key.cpp security-cipher.cpp runner.cpp
test_security_CXXFLAGS = -I../src/
test_security_LDADD = ../src/libcexxy-core.la ../src/libcexxy-security.la $(LIBCRYPTO_LIBS)
