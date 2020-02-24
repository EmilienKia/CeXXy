/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/exceptions.hpp
 * Copyright (C) 2020 Emilien Kia <emilien.kia+dev@gmail.com>
 *
 * libcexxy is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libcexxy is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.";
 */

#ifndef _SECURITY_EXCEPTIONS_HPP_
#define _SECURITY_EXCEPTIONS_HPP_

#include <stdexcept>

namespace cxy
{
namespace security
{

class security_exception : public std::runtime_error
{
public:
    explicit security_exception() : std::runtime_error(""){}
    explicit security_exception(const std::string& what_arg ) : std::runtime_error(what_arg){}
    explicit security_exception(const char* what_arg ) : std::runtime_error(what_arg){}
};

class no_such_algorithm_exception : public security_exception
{
public:
    explicit no_such_algorithm_exception(const std::string& what_arg ) : security_exception(what_arg){}
    explicit no_such_algorithm_exception(const char* what_arg = "" ) : security_exception(what_arg){}
};

class no_such_padding_exception  : public security_exception
{
public:
    explicit no_such_padding_exception(const std::string& what_arg ) : security_exception(what_arg){}
    explicit no_such_padding_exception(const char* what_arg = "" ) : security_exception(what_arg){}
};

class illegal_block_size_exception  : public security_exception
{
public:
    explicit illegal_block_size_exception(const std::string& what_arg ) : security_exception(what_arg){}
    explicit illegal_block_size_exception(const char* what_arg = "" ) : security_exception(what_arg){}
};

class digest_exception : public security_exception
{
public:
    explicit digest_exception(const std::string& what_arg ) : security_exception(what_arg){}
    explicit digest_exception(const char* what_arg = "" ) : security_exception(what_arg){}
};


class key_exception : public security_exception
{
public:
    explicit key_exception(const std::string& what_arg ) : security_exception(what_arg){}
    explicit key_exception(const char* what_arg = "" ) : security_exception(what_arg){}
};

class invalid_key_exception : public key_exception
{
public:
    explicit invalid_key_exception(const std::string& what_arg ) : key_exception(what_arg){}
    explicit invalid_key_exception(const char* what_arg = "" ) : key_exception(what_arg){}
};


}} // namespace cxy::security
#endif // _SECURITY_EXCEPTIONS_HPP_
