/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * io/reader.hpp
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

#ifndef _IO_READER_HPP_
#define _IO_READER_HPP_

#include <string>

#include "exceptions.hpp"

namespace cxy
{
namespace io
{


template<
    class CharT,
    class Traits = std::char_traits<CharT>,
    class Allocator = std::allocator<CharT>
>
class reader
{
public:
	typedef CharT 								char_type;
	typedef Traits 								traits_type;
	typedef Allocator							alloc_type;
	typedef typename traits_type::int_type 		int_type;
	typedef typename alloc_type::size_type		size_type;

	virtual void close() /*throw(io_exception)*/ {}
	virtual size_type available()const {return 0;}
	virtual int_type  read() /*throw(io_exception)*/ = 0;
	virtual size_type read(char_type* ptr, size_type sz) /*throw(std::invalid_argument, io_exception)*/
	{
		if(ptr == nullptr)
			throw std::invalid_argument("cxy::io::reader::read must have non-null ptr.");
		else if(sz == 0)
			return 0;

		int_type c = read();
		if (c == -1) {
			return -1;
		}

		size_type count = 1;
		for(; count < sz ; count++) {
			c = read();
			if (c == -1) {
				break;
			}
			ptr[count] = c;
		}
		return count;
	}

	virtual size_type skip(size_type sz) /*throw(io_exception)*/
	{
		size_t count = 0;
		for(; count < sz ; count++) {
			int_type c = read();
			if (c == -1) {
				break;
			}
		}
		return count;
	}

protected:
	reader(){}
	virtual ~reader(){close();}
};





template<
    class CharT,
    class Traits = std::char_traits<CharT>,
    class Allocator = std::allocator<CharT>
>
class writer
{
public:
	typedef CharT 								char_type;
	typedef Traits 								traits_type;
	typedef Allocator							alloc_type;
	typedef typename traits_type::int_type 		int_type;
	typedef typename alloc_type::size_type		size_type;

	virtual void close() /*throw(io_exception)*/ {flush();}
	virtual void flush() /*throw(io_exception)*/ {}

	virtual void write(char_type ch) /*throw(io_exception)*/ = 0;
	virtual void write(const char_type* ptr, size_type sz) /*throw(std::invalid_argument, io_exception)*/
	{
		if(ptr == nullptr)
			throw std::invalid_argument("cxy::io::writer::write must have non-null ptr.");

		for(size_type count = 0; count < sz ; count++) {
			write(ptr[count]);
		}
	}

protected:
	writer(){}
	virtual ~writer(){close();}
};



template<
    class CharT,
    class Traits = std::char_traits<CharT>,
    class Allocator = std::allocator<CharT>
>
class filter_reader : public reader<CharT, Traits, Allocator>
{
public:
	typedef reader<CharT, Traits, Allocator>	reader_type;
	typedef CharT 								char_type;
	typedef Traits 								traits_type;
	typedef Allocator							alloc_type;
	typedef typename traits_type::int_type 		int_type;
	typedef typename alloc_type::size_type		size_type;

	virtual void close() /*throw(io_exception)*/
	{
		if(_reader!=nullptr)
			_reader->close();
	}
	virtual size_type available()const
	{
		return _reader!=nullptr ? _reader->available() : 0;
	}
	virtual int_type  read() /*throw(io_exception)*/
	{
		return _reader!=nullptr ? _reader->read() : -1;
	}
	virtual size_type read(char_type* ptr, size_type sz) /*throw(std::invalid_argument, io_exception)*/
	{
		return _reader!=nullptr ? _reader->read(ptr, sz) : 0;
	}
	virtual size_type skip(size_type sz) /*throw(io_exception)*/
	{
		return _reader!=nullptr ? _reader->skip() : 0;
	}
protected:
	filter_reader(reader_type *reader):_reader(reader){}
	virtual ~filter_reader(){}

	void set_reader(reader_type *reader){_reader = reader;}
	reader_type* get_reader()const{return _reader;}

private:
	reader_type* _reader;
};



template<
    class CharT,
    class Traits = std::char_traits<CharT>,
    class Allocator = std::allocator<CharT>
>
class filter_writer : public writer<CharT, Traits, Allocator>
{
public:
	typedef writer<CharT, Traits, Allocator>	writer_type;
	typedef CharT 								char_type;
	typedef Traits 								traits_type;
	typedef Allocator							alloc_type;
	typedef typename traits_type::int_type 		int_type;
	typedef typename alloc_type::size_type		size_type;

	virtual void close() /*throw(io_exception)*/
	{
		if(_writer!=nullptr)
			_writer->close();
	}
	virtual void flush() /*throw(io_exception)*/
	{
		if(_writer!=nullptr)
			_writer->flush();
	}
	virtual void write(char_type ch) /*throw(io_exception)*/
	{
		if(_writer!=nullptr)
			_writer->write(ch);
	}
	virtual void write(const char_type* ptr, size_type sz) /*throw(std::invalid_argument, io_exception)*/
	{
		if(_writer!=nullptr)
			_writer->write(ptr, sz);
	}

protected:
	filter_writer(writer_type *writer):_writer(writer){}
	virtual ~filter_writer(){}

	void set_writer(writer_type *writer){_writer = writer;}
	writer_type* get_writer()const{return _writer;}

private:
	writer_type* _writer;
};


template<
    class CharT,
    class Traits = std::char_traits<CharT>,
    class Allocator = std::allocator<CharT>
>
class string_reader : public reader<CharT, Traits, Allocator>
{
public:
	typedef reader<CharT, Traits, Allocator>	reader_type;
	typedef std::basic_string<CharT, Traits, Allocator> string_type;
	typedef CharT 								char_type;
	typedef Traits 								traits_type;
	typedef Allocator							alloc_type;
	typedef typename traits_type::int_type 		int_type;
	typedef typename alloc_type::size_type		size_type;

	string_reader(const string_type& string):_string(string),_pos(0){}
	virtual ~string_reader(){}

	virtual size_type available()const
	{
		return _string.size()>_pos ? _string.size()-_pos : 0;
	}
	virtual int_type  read() /*throw(io_exception)*/
	{
		if(_string.size()>_pos)
			return _string[_pos++];
		else
			return -1;
	}
	virtual size_type read(char_type* ptr, size_type sz) /*throw(std::invalid_argument, io_exception)*/
	{
		if(_pos >= _string.size())
			return -1;
		size_type count = 0;
		while(count<sz && _pos<_string.size())
		{
			ptr[count++] = _string[_pos++];
		}
		return count;
	}
	virtual size_type skip(size_type sz) /*throw(io_exception)*/
	{
		size_type diff = std::min(sz, _string.size()-_pos);
		_pos += diff;
		return diff;
	}

private:
	string_type _string;
	size_type	_pos;
};


template<
    class CharT,
    class Traits = std::char_traits<CharT>,
    class Allocator = std::allocator<CharT>
>
class string_writer : public writer<CharT, Traits, Allocator>
{
public:
	typedef writer<CharT, Traits, Allocator>	writer_type;
	typedef std::basic_string<CharT, Traits, Allocator> string_type;
	typedef CharT 								char_type;
	typedef Traits 								traits_type;
	typedef Allocator							alloc_type;
	typedef typename traits_type::int_type 		int_type;
	typedef typename alloc_type::size_type		size_type;

	string_writer(){}
	virtual ~string_writer(){}

	virtual void close() /*throw(io_exception)*/
	{
	}
	virtual void flush() /*throw(io_exception)*/
	{
	}
	virtual void write(char_type ch) /*throw(io_exception)*/
	{
		_string.push_back(ch);
	}
	virtual void write(const char_type* ptr, size_type sz) /*throw(std::invalid_argument, io_exception)*/
	{
		_string.insert(_string.end(), ptr, ptr+sz);
	}
	virtual size_type size()const
	{
		return _string.size();
	}
	const string_type& str()const
	{
		return _string;
	}
private:
	string_type _string;
};

}} // namespace cxy::io
#endif // _IO_READER_HPP_
