/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * io/exceptions.hpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
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

#ifndef _IO_EXCEPTIONS_HPP_
#define _IO_EXCEPTIONS_HPP_

#include <stdexcept>

namespace cxy
{
namespace io
{

class io_exception : public std::runtime_error
{
public:
    explicit io_exception() : std::runtime_error(""){}
    explicit io_exception(const std::string& what_arg ) : std::runtime_error(what_arg){}
    explicit io_exception(const char* what_arg ) : std::runtime_error(what_arg){}
};

class file_not_found_exception : public io_exception
{
public:
    explicit file_not_found_exception(const std::string& what_arg ) : io_exception(what_arg){}
    explicit file_not_found_exception(const char* what_arg ) : io_exception(what_arg){}
};

class encoder_exception  : public io_exception
{
public:
    explicit encoder_exception(const std::string& what_arg ) : io_exception(what_arg){}
    explicit encoder_exception(const char* what_arg ) : io_exception(what_arg){}
};

class decoder_exception  : public io_exception
{
public:
    explicit decoder_exception(const std::string& what_arg ) : io_exception(what_arg){}
    explicit decoder_exception(const char* what_arg ) : io_exception(what_arg){}
};

}} // namespace cxy::io
#endif // _IO_EXCEPTIONS_HPP_
