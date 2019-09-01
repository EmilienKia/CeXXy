
AM_CPPFLAGS = \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_SRC_DIR=\""$(srcdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\"

AM_CFLAGS =\
	 -Wall\
	 -g

AM_CXXFLAGS = -std=c++11


lib_LTLIBRARIES = libcexxy-core.la

libcexxy_core_la_SOURCES = \
	io/codec.hpp io/codec.cpp \
	io/exceptions.hpp io/exceptions.cpp \
	io/file.hpp io/file.cpp \
	io/reader.hpp io/reader.cpp \
	io/stream.hpp io/stream.cpp \
	math/big-integer.hpp math/big-integer.cpp

libcexxy_core_la_CXXFLAGS =
