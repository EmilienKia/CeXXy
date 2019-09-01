/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * io/file.cpp
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

#include "file.hpp"

namespace cxy
{
namespace io
{

struct file_descriptor_destructor {
    void operator()(std::FILE* file) const {
        if(file!=nullptr)
			fclose(file);
    }
};

//
// file_descriptor
//
file_descriptor::file_descriptor():
_file(nullptr, file_descriptor_destructor())
{
}

file_descriptor::file_descriptor(const file_descriptor& fd):
_file(fd._file)
{
}

file_descriptor::file_descriptor(std::FILE* file):
_file(file, file_descriptor_destructor())
{
}

file_descriptor::~file_descriptor()
{
	close();
}

bool file_descriptor::valid()const
{
	return _file.get() != nullptr;
}

void file_descriptor::close()
{
	_file.reset();
}

file_descriptor file_descriptor::in(stdin);
file_descriptor file_descriptor::out(stdout);
file_descriptor file_descriptor::err(stderr);

//
// file_input_stream
//
file_input_stream::file_input_stream(const std::string& name)
{
	FILE* file = fopen(name.c_str(), "r+b");
	if(file!=nullptr)
	{
		_file = file_descriptor(file);
	}
	else
	{
		throw file_not_found_exception(std::string("File '").append(name).append("' not found."));
	}
}

file_input_stream::file_input_stream(const file_descriptor& fd):
_file(fd)
{
}

file_input_stream::~file_input_stream()
{
}

void file_input_stream::close()
{
	_file.close();
}

int file_input_stream::read()
{
	if(!_file.valid())
		throw io_exception(/* TODO Change or specify exception. */);

	int c = std::fgetc(_file.get());
	if(c != EOF)
	{
		return c;
	}
	else
	{
		if(std::feof(_file.get()))
		{
			return -1;
		}
		else
		{
			throw io_exception("Error while reading byte from file_input_stream.");
		}
	}
}

int file_input_stream::read(void* ptr, std::size_t sz)
{
	if(ptr == nullptr)
		throw std::invalid_argument("file_input_stream::read must have non-null ptr.");
	else if(sz == 0)
		return 0;
	if(!_file.valid())
		throw io_exception(/* TODO Change or specify exception. */);

	std::size_t count = std::fread(ptr, sizeof(std::uint8_t), sz, _file.get());

	return (int)count;
}

std::size_t file_input_stream::skip(std::size_t sz)
{
	if(!_file.valid())
		throw io_exception(/* TODO Change or specify exception. */);

	long pos1 = std::ftell(_file.get());
	if(pos1 == -1)
	{
		throw io_exception("Error while skipping bytes in io::FileInputrStream");
	}

	if(std::fseek(_file.get(), (long) sz, SEEK_CUR ) != 0)
	{
		throw io_exception("Error while skipping bytes in io::FileInputrStream");
	}

	long pos2 = std::ftell(_file.get());
	if(pos2 == -1)
	{
		throw io_exception("Error while skipping bytes in io::FileInputrStream");
	}

	return pos2 - pos1;
}

file_descriptor file_input_stream::get_file_descriptor()const
{
	return _file;
}

//
// file_output_stream
//
file_output_stream::file_output_stream(const std::string& name, bool append)
{
	FILE* file = fopen(name.c_str(), append ? "a+b" : "w+b");
	if(file!=nullptr)
	{
		_file = file_descriptor(file);
	}
	else
	{
		throw file_not_found_exception(std::string("File '").append(name).append("' not found."));
	}
}

file_output_stream::file_output_stream(const file_descriptor& fd):
_file(fd)
{
}

file_output_stream::~file_output_stream()
{
}

void file_output_stream::close()
{
	_file.close();
}

void file_output_stream::flush()
{
	if(!_file.valid())
		throw io_exception(/* TODO Change or specify exception. */);
	if(fflush(_file.get()) == EOF)
		throw io_exception("Error while flushing file_output_stream.");
}

void file_output_stream::write(std::uint8_t byte)
{
	if(!_file.valid())
		throw io_exception(/* TODO Change or specify exception. */);

	if(std::fputc(byte, _file.get()) == EOF)
		throw io_exception("Error while writing byte to file_output_stream.");
}

void file_output_stream::write(const void* ptr, std::size_t sz)
{
	if(ptr == nullptr)
		throw std::invalid_argument("OutputStream::write must have non-null ptr.");

	if(sz > 0)
	{
		std::size_t count = fwrite(ptr, sizeof(std::uint8_t), sz, _file.get());
		if(count<sz)
			throw io_exception("Error while writing to file_output_stream.");
	}
}

file_descriptor file_output_stream::get_file_descriptor()const
{
	return _file;
}

}} // namespace cxy::io
