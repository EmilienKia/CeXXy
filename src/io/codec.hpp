/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * io/codec.hpp
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

#ifndef _IO_CODEC_HPP_
#define _IO_CODEC_HPP_

#include "exceptions.hpp"
#include "stream.hpp"

#include <array>
#include <bitset>
#include <deque>
#include <iostream>
#include <memory>
#include <vector>

namespace cxy
{
namespace io
{
namespace codec
{

class percent_encoding;
class percent_decoding;
class form_url_encoding;
class form_url_decoding;

/**
 * Basic codec structure.
 */
struct codec
{
public:
    bool          _eof   = false; // Is EOF reached ?
    size_t        _state = 0; // State, stage or modulus
    std::uint64_t _work  = 0; // Working cache
    std::deque<std::uint8_t> _buffer; // Buffer where are stored intermediate already processed data

    virtual void process(const std::uint8_t* buff, size_t len) = 0;

    virtual void finalize()
    {
        _eof = true;
    }

    virtual int read(std::uint8_t* buff, size_t len)
    {
        if(_eof && _buffer.empty())
            return -1;
        size_t sz = std::min(len, _buffer.size());
        if(sz>0)
        {
            for(size_t n=0; n<sz; ++n)
            {
                buff[n] = _buffer[n];
            }
            _buffer.erase(_buffer.begin(), _buffer.begin()+sz);
        }
        return sz;
    }

#if 0 // MANUAL DEBUG ONLY
    void dump()
    {
        std::cout << "Buffer[eof=" << _eof << ",state=" << _state << ",work=" << std::hex << _work << ",buffer(" << _buffer.size() <<"):";
        for(size_t n=0; n<_buffer.size(); ++n)
        {
            std::cout << (char)_buffer[n];
        }
        std::cout << "]" << std::endl;
    }
#endif // 0 // MANUAL DEBUG ONLY
};


/**
 * Base codec input stream.
 */
template<typename codec, size_t buffsz = 4096>
class codec_input_stream : public filter_input_stream
{
public:
    typedef codec codec_t;

    virtual std::size_t available()const
    {
        return _codec._eof ? 0 : _codec._buffer.size();
    }

    virtual int read() /*throw(IOException)*/
    {
        std::uint8_t c;
        int r;
        do {
            r = read(&c, 1);
        } while (r == 0);
        return r > 0 ? c : -1;
    }

    virtual int read(void* ptr, std::size_t sz) /*throw(std::invalid_argument, IOException)*/
    {
        if(ptr == nullptr)
            throw std::invalid_argument("cxy::io::codec::codec_input_stream::read must have non-null ptr.");
        if(sz==0)
            return 0;
        if(_codec._eof && _codec._buffer.size() == 0)
            return -1;

        std::array<std::uint8_t, buffsz> buf;

        int readLen = 0;
        while (readLen == 0) {
            if (_codec._buffer.empty()) {
                int c = filter_input_stream::read(buf.data(), buffsz);
                if(c<0)
                {
                    _codec.finalize();
                }
                else
                {
                    _codec.process(buf.data(), c);
                }
            }
            readLen = _codec.read((uint8_t*)ptr, sz);
        }
        return readLen;
    }

    virtual std::size_t skip(std::size_t sz) /*throw(IOException)*/
    {
        std::uint8_t buffer[buffsz];
        std::size_t todo = sz;

        while(todo > 0)
        {
            size_t len = std::min((size_t)buffsz, (size_t)todo);
            int res = read(buffer, len);
            if(res==-1)
            {
                break;
            }
            todo -= res;
        }
        return sz-todo;
    }

protected:
    codec_input_stream(input_stream* stream):
    filter_input_stream(stream),
    _codec()
    {
    }

    template<typename... Arguments>
    codec_input_stream(input_stream* stream, Arguments... parameters):
    filter_input_stream(stream),
    _codec(parameters...)
    {
    }

    codec_t _codec;
};


/**
 * Basic codec output stream.
 */
template<typename codec>
class codec_output_stream : public filter_output_stream
{
public:
    typedef codec codec_t;

    virtual void close()
    {
        _codec.finalize();
        flush();
        filter_output_stream::close();
    }

    virtual void flush() /*throw(IOException)*/
    {
        flush(true);
    }

    virtual void write(std::uint8_t byte) /*throw(IOException)*/
    {
        write(&byte, 1);
    }

    virtual void write(const void* ptr, std::size_t sz) /*throw(std::invalid_argument, IOException)*/
    {
        if(ptr == nullptr)
            throw std::invalid_argument("cxy::io::codec::codec_output_stream::write must have non-null ptr.");
        else if(sz>0)
        {
            _codec.process((const std::uint8_t*)ptr, sz);
            flush(false);
        }
    }

private:
    void flush(bool propagate) /*throw(IOException)*/
    {
        size_t avail = _codec._buffer.size();
        if(avail>0)
        {
            std::vector<std::uint8_t> buf(avail);
            int c = _codec.read(buf.data(), avail);
            if(c>0)
            {
                filter_output_stream::write(buf.data(), c);
            }
        }
        if(propagate)
        {
            filter_output_stream::flush();
        }
    }

protected:
    codec_output_stream(output_stream* stream):
    filter_output_stream(stream),
    _codec()
    {
    }

    template<typename... Arguments>
    codec_output_stream(output_stream* stream, Arguments... parameters):
    filter_output_stream(stream),
    _codec(parameters...)
    {
    }

    codec_t _codec;
};










/**
 * Basic codec for BaseN encoding.
 */
class base_n_codec : public codec
{
public:
    enum {
        PAD_DEFAULT = '=',
        DEFAULT_BUFFER_SIZE = 8192,


        MIME_CHUNK_SIZE = 76,
        PEM_CHUNK_SIZE = 64,


        MASK_5BITS = 0x1f,
        MASK_6BITS = 0x3f,
        MASK_8BITS = 0xff

    };

    static bool isWhitespace(std::uint8_t c);

protected:
    base_n_codec(size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>(), std::uint8_t pad = PAD_DEFAULT);

    virtual void addSeparator();

    std::uint8_t _pad;

    std::size_t  _lineLength; // Line length (0 to not add chenk separator)
    std::size_t _currentLinePos = 0; // Current pos in current line
    std::vector<std::uint8_t> _separator; // Separator to be inserted at each end of line.

};

/**
 * Base declarations for Base64 coding
 */
class base64_codec : public base_n_codec
{
public:
    enum {
        BITS_PER_ENCODED_BYTE = 6,
        BYTES_PER_UNENCODED_BLOCK = 3,
        BYTES_PER_ENCODED_BLOCK = 4
    };

    typedef std::array<std::uint8_t, 64> encoding_table;
    typedef std::array<std::int8_t, 256> decoding_table;

protected:
    base64_codec(size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>(), std::uint8_t pad = PAD_DEFAULT);
};

/**
 * Base64 encoding.
 */
class base64_encoding : public base64_codec
{
public:

    base64_encoding(size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
    base64_encoding(encoding_table& table, std::uint8_t pad = PAD_DEFAULT, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
    base64_encoding(bool urlSafe, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());

    virtual void process(const std::uint8_t* buff, size_t len);
    virtual void finalize();

protected:
    encoding_table& _table;

    static encoding_table STANDARD_ENCODE_TABLE, URL_SAFE_ENCODE_TABLE;

};

/**
 * Base64 encoding input stream.
 */
class base64_encoding_input_stream : public codec_input_stream<base64_encoding>
{
public:
    base64_encoding_input_stream(input_stream* stream);
    base64_encoding_input_stream(input_stream* stream, size_t lineLength, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
    base64_encoding_input_stream(input_stream* stream, base64_codec::encoding_table& table, std::uint8_t pad = base_n_codec::PAD_DEFAULT, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
    base64_encoding_input_stream(input_stream* stream, bool urlSafe, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
};

/**
 * Base64 encoding output stream.
 */
class base64_encoding_output_stream : public codec_output_stream<base64_encoding>
{
public:
    base64_encoding_output_stream(output_stream* stream);
    base64_encoding_output_stream(output_stream* stream, size_t lineLength, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
    base64_encoding_output_stream(output_stream* stream, base64_codec::encoding_table& table, std::uint8_t pad = base_n_codec::PAD_DEFAULT, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
    base64_encoding_output_stream(output_stream* stream, bool urlSafe, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
};



/**
 * Base64 decoding
 */
class base64_decoding : public base64_codec
{
public:
    virtual void process(const std::uint8_t* buff, size_t len);

private:
    static decoding_table DECODE_TABLE;

};


/**
 * Base64 decoding input stream
 */
class base64_decoding_input_stream : public codec_input_stream<base64_decoding>
{
public:
    base64_decoding_input_stream(input_stream* stream);
};

/**
 * Base64 decoding output stream
 */
class base64_decoding_output_stream : public codec_output_stream<base64_decoding>
{
public:
    base64_decoding_output_stream(output_stream* stream);
};






/**
 * Base declarations for Base32 coding
 */
class base32_codec : public base_n_codec
{
public:
    enum {
        BITS_PER_ENCODED_BYTE = 5,
        BYTES_PER_UNENCODED_BLOCK = 5,
        BYTES_PER_ENCODED_BLOCK = 8
    };

    typedef std::array<std::uint8_t, 32> encoding_table;
    typedef std::array<std::int8_t, 256> decoding_table;

protected:
    base32_codec(size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>(), std::uint8_t pad = PAD_DEFAULT);

};

/**
 * Base32 encoding.
 */
class base32_encoding : public base32_codec
{
public:
    base32_encoding(encoding_table& table, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>(), std::uint8_t pad = PAD_DEFAULT);
    base32_encoding(bool useHex = false, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>(), std::uint8_t pad = PAD_DEFAULT);

    virtual void process(const std::uint8_t* buff, size_t len);
    virtual void finalize();

protected:
    encoding_table& _table;

    static encoding_table STANDARD_ENCODE_TABLE, HEX_STANDARD_ENCODE_TABLE;

};

/**
 * Base32 encoding input stream.
 */
class base32_encoding_input_stream : public codec_input_stream<base32_encoding>
{
public:
    base32_encoding_input_stream(input_stream* stream);
    base32_encoding_input_stream(input_stream* stream, base32_codec::encoding_table& table, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>(), std::uint8_t pad = base_n_codec::PAD_DEFAULT);
    base32_encoding_input_stream(input_stream* stream, bool useHex, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>(), std::uint8_t pad = base_n_codec::PAD_DEFAULT);
};

/**
 * Base32 encoding output stream.
 */
class base32_encoding_output_stream : public codec_output_stream<base32_encoding>
{
public:
    base32_encoding_output_stream(output_stream* stream);
    base32_encoding_output_stream(output_stream* stream, base32_codec::encoding_table& table, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>(), std::uint8_t pad = base_n_codec::PAD_DEFAULT);
    base32_encoding_output_stream(output_stream* stream, bool useHex, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>(), std::uint8_t pad = base_n_codec::PAD_DEFAULT);
};

/**
 * Base32 decoding
 */
class base32_decoding : public base32_codec
{
public:
    base32_decoding(bool useHex = false);
    base32_decoding(base32_codec::decoding_table& table);
    virtual void process(const std::uint8_t* buff, size_t len);

protected:
    decoding_table& _table;

    static decoding_table STANDARD_DECODE_TABLE, HEX_STANDARD_DECODE_TABLE;

};


/**
 * Base32 decoding input stream
 */
class base32_decoding_input_stream : public codec_input_stream<base32_decoding>
{
public:
    base32_decoding_input_stream(input_stream* stream, bool useHex = false);
    base32_decoding_input_stream(input_stream* stream, base32_codec::decoding_table& table);
};

/**
 * Base32 decoding output stream
 */
class base32_decoding_output_stream : public codec_output_stream<base32_decoding>
{
public:
    base32_decoding_output_stream(output_stream* stream, bool useHex = false);
    base32_decoding_output_stream(output_stream* stream, base32_codec::decoding_table& table);
};








/**
 * Base declarations for Base16 (aka Hex) coding
 */
class base16_codec : public base_n_codec
{
public:
    enum {
        BITS_PER_ENCODED_BYTE = 4 ,
        BYTES_PER_ENCODED_BLOCK = 2
    };

    typedef std::array<std::uint8_t, 16> encoding_table;
    typedef std::array<std::int8_t, 256> decoding_table;

protected:
    base16_codec(size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
};


/**
 * Base16 encoding.
 */
class base16_encoding : public base16_codec
{
public:
    base16_encoding(encoding_table& table, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
    base16_encoding(bool useUppercase = true, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());

    virtual void process(const std::uint8_t* buff, size_t len);

protected:
    encoding_table& _table;

    static encoding_table UPPERCASE_ENCODE_TABLE, LOWERCASE_ENCODE_TABLE;

    friend class percent_encoding; // Let it access to UPPERCASE_ENCODE_TABLE
    friend class form_url_encoding; // Let it access to UPPERCASE_ENCODE_TABLE
};

/**
 * Base16 encoding input stream.
 */
class base16_encoding_input_stream : public codec_input_stream<base16_encoding>
{
public:
    base16_encoding_input_stream(input_stream* stream);
    base16_encoding_input_stream(input_stream* stream, base16_codec::encoding_table& table, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
    base16_encoding_input_stream(input_stream* stream, bool useUppercase, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
};

/**
 * Base16 encoding output stream.
 */
class base16_encoding_output_stream : public codec_output_stream<base16_encoding>
{
public:
    base16_encoding_output_stream(output_stream* stream);
    base16_encoding_output_stream(output_stream* stream, base16_codec::encoding_table& table, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
    base16_encoding_output_stream(output_stream* stream, bool useUppercase, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
};

/**
 * Base16 decoding
 */
class base16_decoding : public base16_codec
{
public:
    base16_decoding();
    base16_decoding(base16_codec::decoding_table& table);

    virtual void process(const std::uint8_t* buff, size_t len);

protected:
    decoding_table& _table;

    static decoding_table STANDARD_DECODE_TABLE;

    friend class percent_decoding; // Let it access to UPPERCASE_ENCODE_TABLE
    friend class form_url_decoding; // Let it access to UPPERCASE_ENCODE_TABLE
};


/**
 * Base16 decoding input stream
 */
class base16_decoding_input_stream : public codec_input_stream<base16_decoding>
{
public:
    base16_decoding_input_stream(input_stream* stream);
    base16_decoding_input_stream(input_stream* stream, base16_codec::decoding_table& table);
};

/**
 * Base16 decoding output stream
 */
class base16_decoding_output_stream : public codec_output_stream<base16_decoding>
{
public:
    base16_decoding_output_stream(output_stream* stream);
    base16_decoding_output_stream(output_stream* stream, base16_codec::decoding_table& table);
};

typedef base16_encoding_input_stream HexEncodinginput_stream;
typedef base16_encoding_output_stream HexEncodingoutput_stream;
typedef base16_decoding_input_stream HexDecodinginput_stream;
typedef base16_decoding_output_stream HexDecodingoutput_stream;







/**
 * Base declarations for Base2 (aka Bin) coding
 */
class base2_codec : public base_n_codec
{
public:
    enum {
        BITS_PER_ENCODED_BYTE = 1,
        BYTES_PER_ENCODED_BLOCK = 8
    };

protected:
    base2_codec(size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());


    static std::array<uint8_t, 8> bits;
};


/**
 * Base2 encoding.
 */
class base2_encoding : public base2_codec
{
public:
    base2_encoding(size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());

    virtual void process(const std::uint8_t* buff, size_t len);
};

/**
 * Base2 encoding input stream.
 */
class base2_encoding_input_stream : public codec_input_stream<base2_encoding>
{
public:
    base2_encoding_input_stream(input_stream* stream, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
};

/**
 * Base2 encoding output stream.
 */
class base2_encoding_output_stream : public codec_output_stream<base2_encoding>
{
public:
    base2_encoding_output_stream(output_stream* stream, size_t lineLength = 0, std::vector<std::uint8_t> separator = std::vector<std::uint8_t>());
};

/**
 * Base2 decoding
 */
class base2_decoding : public base2_codec
{
public:
    base2_decoding();

    virtual void process(const std::uint8_t* buff, size_t len);
};


/**
 * Base2 decoding input stream
 */
class base2_decoding_input_stream : public codec_input_stream<base2_decoding>
{
public:
    base2_decoding_input_stream(input_stream* stream);
};

/**
 * Base2 decoding output stream
 */
class base2_decoding_output_stream : public codec_output_stream<base2_decoding>
{
public:
    base2_decoding_output_stream(output_stream* stream);
};

typedef base2_encoding_input_stream bin_encoding_input_stream;
typedef base2_encoding_output_stream bin_encoding_output_stream;
typedef base2_decoding_input_stream bin_decoding_input_stream;
typedef base2_decoding_output_stream bin_decoding_output_stream;





/**
 * Percent encoding.
 */
class percent_codec : public codec
{
public:
    typedef std::bitset<256> encoding_table;

protected:
    percent_codec() = default;
};

/**
 * Percent encoding.
 */
class percent_encoding : public percent_codec
{
public:
    percent_encoding();
    percent_encoding(encoding_table& table);

    virtual void process(const std::uint8_t* buff, size_t len);

protected:
    encoding_table& _table;

    static encoding_table ENCODE_TABLE;
};

/**
 * Percent decoding.
 */
class percent_decoding : public percent_codec
{
public:
    percent_decoding();

    virtual void process(const std::uint8_t* buff, size_t len);
};

/**
 * Percent encoding input stream.
 */
class percent_encoding_input_stream : public codec_input_stream<percent_encoding>
{
public:
    percent_encoding_input_stream(input_stream* stream);
    percent_encoding_input_stream(input_stream* stream, percent_codec::encoding_table& table);
};

/**
 * Percent encoding output stream.
 */
class percent_encoding_output_stream : public codec_output_stream<percent_encoding>
{
public:
    percent_encoding_output_stream(output_stream* stream);
    percent_encoding_output_stream(output_stream* stream, percent_codec::encoding_table& table);
};

/**
 * Percent decoding input stream
 */
class percent_decoding_input_stream : public codec_input_stream<percent_decoding>
{
public:
    percent_decoding_input_stream(input_stream* stream);
};

/**
 * Percent decoding output stream
 */
class percent_decoding_output_stream : public codec_output_stream<percent_decoding>
{
public:
    percent_decoding_output_stream(output_stream* stream);
};






/**
 * Form URL Encoding for application/x-www-form-urlencoded encoded data.
 */
class form_url_encoding : public percent_encoding
{
public:
    form_url_encoding() = default;
    void process(const std::uint8_t* buff, size_t len);
};

/**
 * Form URL Decoding for application/x-www-form-urlencoded decoded data.
 */
class form_url_decoding : public percent_decoding
{
public:
    form_url_decoding() = default;
    void process(const std::uint8_t* buff, size_t len);
};


/**
 * Form URL encoding input stream.
 */
class form_url_encoding_input_stream : public codec_input_stream<form_url_encoding>
{
public:
    form_url_encoding_input_stream(input_stream* stream);
};

/**
 * Form URL encoding output stream.
 */
class form_url_encoding_output_stream : public codec_output_stream<form_url_encoding>
{
public:
    form_url_encoding_output_stream(output_stream* stream);
};

/**
 * Form URL decoding input stream
 */
class form_url_decoding_input_stream : public codec_input_stream<form_url_decoding>
{
public:
    form_url_decoding_input_stream(input_stream* stream);
};

/**
 * Form URL decoding output stream
 */
class form_url_decoding_output_stream : public codec_output_stream<form_url_decoding>
{
public:
    form_url_decoding_output_stream(output_stream* stream);
};



}}} // namespace cxy::io::codec
#endif // _IO_BIN2TEXT_HPP_
