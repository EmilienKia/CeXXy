/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * io/stream.cpp
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

#include "stream.hpp"

#include <exception>
#include <iostream>

namespace cxy
{
namespace io
{

//
// Input stream
//

void input_stream::close()
{
}

std::size_t input_stream::available()const
{
    return 0;
}

int input_stream::read(void* ptr, std::size_t sz)
{
    if(ptr == nullptr)
        throw std::invalid_argument("cxy::io::input_stream::read must have non-null ptr.");
    else if(sz == 0)
        return 0;

    std::uint8_t* arr = (std::uint8_t*)ptr;

    int c = read();
    if (c == -1) {
        return -1;
    }
    *arr = (std::uint8_t)c;

    int count = 1;
    for(; count < sz ; count++) {
        c = read();
        if (c == -1) {
            break;
        }
        arr[count] = (std::uint8_t)c;
    }
    return count;
}

std::size_t input_stream::skip(std::size_t sz)
{
    std::size_t count = 0;
    for(; count < sz ; count++) {
        int c = read();
        if (c == -1) {
            break;
        }
    }
    return count;
}

void input_stream::write_to(output_stream* outstream, size_t buffsz)
{
    if(outstream == nullptr)
        throw std::invalid_argument("cxy::io::input_stream::writeTo must have non-null outstream.");
    if(buffsz == 0)
        buffsz = 4096;

    std::uint8_t *buffer = new std::uint8_t[buffsz];
    while(true)
    {
        for(size_t n=0; n<buffsz; ++n)
            buffer[n] = 0;

        int res = read(buffer, buffsz);
        if(res == -1)
        {
            break;
        }
        if(res > 0)
        {
            outstream->write(buffer, res);
        }
    }
    delete [] buffer;
    outstream->close();
}

//
// Output stream
//

void output_stream::close()
{
    flush();
}

void output_stream::flush()
{
}

void output_stream::write(const void* ptr, std::size_t sz)
{
    if(ptr == nullptr)
        throw std::invalid_argument("cxy::io::output_stream::write must have non-null ptr.");

    const std::uint8_t* arr = (std::uint8_t*)ptr;
    for(std::size_t count = 0; count < sz ; count++) {
        write(arr[count]);
    }
}

//
// filter_input_stream
//
filter_input_stream::filter_input_stream(input_stream *stream):
_stream(stream)
{
}

void filter_input_stream::close()
{
    if(_stream!=nullptr)
        _stream->close();
}

void filter_input_stream::set_input_stream(input_stream *stream)
{
    _stream = stream;
}

input_stream* filter_input_stream::get_input_stream()const
{
    return _stream;
}


std::size_t filter_input_stream::available()const
{
    return _stream!=nullptr ? _stream->available() : 0;
}

int filter_input_stream::read()
{
    return _stream!=nullptr ? _stream->read() : -1;
}

int filter_input_stream::read(void* ptr, std::size_t sz)
{
    return _stream!=nullptr ? _stream->read(ptr, sz) : -1;
}

std::size_t filter_input_stream::skip(std::size_t sz)
{
    return _stream!=nullptr ? _stream->skip(sz) : 0;
}

//
// Filter output stream
//

filter_output_stream::filter_output_stream(output_stream *stream):
_stream(stream)
{
}

void filter_output_stream::set_output_stream(output_stream *stream)
{
    _stream = stream;
}

output_stream* filter_output_stream::get_output_stream()const
{
    return _stream;
}

void filter_output_stream::close()
{
    if(_stream!=nullptr)
        _stream->close();
}

void filter_output_stream::flush()
{
    if(_stream!=nullptr)
        _stream->flush();
}

void filter_output_stream::write(std::uint8_t byte)
{
    if(_stream!=nullptr)
        _stream->write(byte);
}

void filter_output_stream::write(const void* ptr, std::size_t sz)
{
    if(_stream!=nullptr)
        _stream->write(ptr, sz);
}

//
// MemoryInputStream
//

memory_input_stream::memory_input_stream(const void* ptr, std::size_t sz):
_ptr((const std::uint8_t*)ptr),
_sz(sz),
_pos(0)
{
    if(ptr == nullptr)
        throw std::invalid_argument("cxy::io::memory_input_stream must have non-null memory ptr.");
}

std::size_t memory_input_stream::available()const
{
    return _sz > _pos ? _sz - _pos : 0;
}

int memory_input_stream::read()
{
    if(_sz > _pos)
        return _ptr[_pos++];
    else
        return -1;
}

int memory_input_stream::read(void* ptr, std::size_t sz)
{
    std::uint8_t* arr = (std::uint8_t*) ptr;

    if(_pos >= _sz)
        return -1;
    std::size_t count = 0;
    while(count<sz && _pos<_sz)
    {
        arr[count++] = _ptr[_pos++];
    }
    return count;
}

std::size_t memory_input_stream::skip(std::size_t sz)
{
    std::size_t diff = std::min(sz, _sz-_pos);
    _pos += diff;
    return diff;
}

//
// Memory output stream
//
memory_output_stream::memory_output_stream(std::size_t sz)
{
    _buffer.reserve(sz);
}

void memory_output_stream::write(std::uint8_t byte)
{
    _buffer.push_back(byte);
}

void memory_output_stream::write(const void* ptr, std::size_t sz)
{
    if(ptr==nullptr)
        throw std::invalid_argument("cxy::io::memory_output_stream::write must have non-null memory ptr.");
    if(sz>0)
    {
        std::uint8_t* arr = (std::uint8_t*)ptr;
        _buffer.insert(_buffer.end(), arr, arr+sz);
    }
}

void memory_output_stream::reset()
{
    _buffer.clear();
}

std::size_t memory_output_stream::size()const
{
    return _buffer.size();
}

const std::uint8_t* memory_output_stream::data()const
{
    return _buffer.data();
}


void memory_output_stream::write_to(output_stream& out) const
{
    out.write(_buffer.data(), _buffer.size());
}

//
// Data input stream
//

data_input_stream::data_input_stream(input_stream *stream):
filter_input_stream(stream)
{
}


//
// Data Output Stream
//
data_output_stream::data_output_stream(output_stream *stream):
filter_output_stream(stream)
{
}

}} // namespace cxy::io
