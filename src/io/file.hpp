/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * io/file.hpp
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

#ifndef _IO_FILE_HPP_
#define _IO_FILE_HPP_

#include "stream.hpp"

#include <memory>

namespace cxy
{
namespace io
{

class file_input_stream;
class file_output_stream;

class file_descriptor
{
public:
	bool valid()const;

	void close();

	file_descriptor();
	file_descriptor(const file_descriptor& fd);
	file_descriptor(file_descriptor&& fd);
	~file_descriptor();

	file_descriptor& operator=(const file_descriptor& fd);
	file_descriptor& operator=(file_descriptor&& fd);

	static file_descriptor in;
	static file_descriptor out;
	static file_descriptor err;

protected:
	friend class file_input_stream;
	friend class file_output_stream;

	file_descriptor(std::FILE* file);

	std::FILE* get()const{return _file.get();}

	std::shared_ptr<std::FILE> _file;
};


class file_input_stream : public input_stream
{
public:
	file_input_stream(const std::string& name) /*throw(file_not_found_exception)*/;
	file_input_stream(const file_descriptor& fd);
	virtual ~file_input_stream();
	virtual void close();
	virtual int read() /*throw(io_exception)*/;
	virtual int read(void* ptr, std::size_t sz) /*throw(std::invalid_argument, io_exception)*/;
	virtual std::size_t skip(std::size_t sz) /*throw(io_exception)*/;

	virtual file_descriptor get_file_descriptor()const;

protected:
	file_descriptor _file;
};

class file_output_stream : public output_stream
{
public:
	file_output_stream(const std::string& name, bool append=false) /*throw(file_not_found_exception)*/;
	file_output_stream(const file_descriptor& fd);
	virtual ~file_output_stream();
	virtual void close();
	virtual void flush() /*throw(io_exception)*/;
	virtual void write(std::uint8_t byte) /*throw(io_exception)*/;
	virtual void write(const void* ptr, std::size_t sz) /*throw(std::invalid_argument, io_exception)*/;

	virtual file_descriptor get_file_descriptor()const;
protected:
	file_descriptor _file;
};


}} // namespace cxy::io
#endif // _IO_FILE_HPP_
