cmake_minimum_required(VERSION 3.16)
cmake_policy(VERSION 3.16)

project(cexxy VERSION 1.0.0)

# Set C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig)

pkg_check_modules(GMP REQUIRED IMPORTED_TARGET gmp)

pkg_check_modules(LIBCRYPTO REQUIRED IMPORTED_TARGET libcrypto)


add_subdirectory(src)

enable_testing()
add_subdirectory(tests)


