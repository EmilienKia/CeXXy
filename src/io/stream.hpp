/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * io/stream.hpp
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

#ifndef _IO_STREAM_HPP_
#define _IO_STREAM_HPP_

#include <cstdint>
#include <vector>

#include "exceptions.hpp"

namespace cxy
{
namespace io
{

class output_stream;

class input_stream
{
public:
    virtual ~input_stream() = default;
    virtual void close();
    virtual std::size_t available()const;
    virtual int read() /*throw(io_exception)*/ = 0;
    virtual int read(void* ptr, std::size_t sz) /*throw(std::invalid_argument, io_exception)*/;
    virtual std::size_t skip(std::size_t sz) /*throw(io_exception)*/;

    virtual void write_to(output_stream* outstream, size_t buffsz = 4096) /*throw(std::invalid_argument, io_exception)*/;
protected:
    input_stream() = default;
};

class output_stream
{
public:
    virtual ~output_stream() = default;
    virtual void close();
    virtual void flush() /*throw(io_exception)*/;
    virtual void write(std::uint8_t byte) /*throw(io_exception)*/ = 0;
    virtual void write(const void* ptr, std::size_t sz) /*throw(std::invalid_argument, io_exception)*/;
protected:
    output_stream() = default;
};

class filter_input_stream : public input_stream
{
public:
    virtual ~filter_input_stream() = default;

    virtual void close();
    virtual std::size_t available()const;
    virtual int read() /*throw(io_exception)*/;
    virtual int read(void* ptr, std::size_t sz) /*throw(std::invalid_argument, io_exception)*/;
    virtual std::size_t skip(std::size_t sz) /*throw(io_exception)*/;

protected:
    filter_input_stream(input_stream *stream);

    void set_input_stream(input_stream *stream);
    input_stream* get_input_stream()const;

private:
    input_stream* _stream;
};

class filter_output_stream : public output_stream
{
public:
    virtual ~filter_output_stream() = default;
    virtual void close();
    virtual void flush() /*throw(io_exception)*/;
    virtual void write(std::uint8_t byte) /*throw(io_exception)*/;
    virtual void write(const void* ptr, std::size_t sz) /*throw(std::invalid_argument, io_exception)*/;
protected:
    filter_output_stream(output_stream *stream);

    void set_output_stream(output_stream *stream);
    output_stream* get_output_stream()const;

private:
    output_stream* _stream;
};

class memory_input_stream : public input_stream
{
public:
    memory_input_stream(const void* ptr, std::size_t sz) /*throw(std::invalid_argument)*/;
    virtual ~memory_input_stream() = default;

    virtual std::size_t available()const;
    virtual int read() /*throw(io_exception)*/;
    virtual int read(void* ptr, std::size_t sz) /*throw(std::invalid_argument, io_exception)*/;
    virtual std::size_t skip(std::size_t sz) /*throw(io_exception)*/;

protected:
    const std::uint8_t* _ptr;
    std::size_t _sz, _pos;
};

class memory_output_stream : public output_stream
{
public:
    memory_output_stream() = default;
    memory_output_stream(std::size_t sz);
    virtual ~memory_output_stream() = default;
    virtual void write(std::uint8_t byte) /*throw(io_exception)*/;
    virtual void write(const void* ptr, std::size_t sz) /*throw(std::invalid_argument, io_exception)*/;

    virtual void reset();
    virtual std::size_t size()const;
    virtual const std::uint8_t* data()const;

    template<typename T>
    T to()const
    {
        return T(data(), data()+size());
    }

    const std::vector<std::uint8_t>& to() const
    {
        return _buffer;
    }

    virtual void write_to(output_stream& out) const /*throw(io_exception)*/;
protected:
    std::vector<std::uint8_t> _buffer;
};

class data_input_stream : public filter_input_stream
{
public:
    data_input_stream(input_stream *stream);
    virtual ~data_input_stream() = default;

    template<typename T> T read() /*throw(io_exception)*/;

};

template<typename T> T data_input_stream::read() /*throw(io_exception)*/
{
    T buffer;
    filter_input_stream::read((void*)&buffer, sizeof(T));
    return buffer;
}

template<> inline bool data_input_stream::read() /*throw(io_exception)*/
{
    int byte = filter_input_stream::read();
    return byte > 0;
}


class data_output_stream : public filter_output_stream
{
public:
    data_output_stream(output_stream *stream);
    virtual ~data_output_stream() = default;

    template<typename T> void write(T val) /*throw(io_exception)*/;
};

template<typename T> void data_output_stream::write(T val) /*throw(io_exception)*/
{
    filter_output_stream::write(&val, sizeof(T));
}

template<> inline void data_output_stream::write(bool val) /*throw(io_exception)*/
{
    filter_output_stream::write(val ? 0xFF : 0x00);
}

}} // namespace cxy::io
#endif // _IO_STREAM_HPP_
