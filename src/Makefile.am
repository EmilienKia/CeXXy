
AM_CPPFLAGS = \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_SRC_DIR=\""$(srcdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\"

AM_CFLAGS =\
	 -Wall\
	 -g

AM_CXXFLAGS = -std=c++11


lib_LTLIBRARIES = libcexxy-core.la libcexxy-security.la

libcexxy_core_la_SOURCES = \
	io/codec.hpp io/codec.cpp \
	io/exceptions.hpp io/exceptions.cpp \
	io/file.hpp io/file.cpp \
	io/reader.hpp io/reader.cpp \
	io/stream.hpp io/stream.cpp \
	math/big-integer.hpp math/big-integer.cpp

libcexxy_core_la_CXXFLAGS =


libcexxy_security_la_SOURCES = \
	security/key.hpp security/key.cpp \
	security/message-digest.hpp security/message-digest.cpp \
	security/cipher.hpp security/cipher.cpp

libcexxy_security_la_CXXFLAGS =
