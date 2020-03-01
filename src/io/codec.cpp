/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * io/codec.cpp
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

#include "codec.hpp"

#include <vector>
#include <algorithm>

namespace cxy
{
namespace io
{
namespace codec
{

//
// base_n_codec
//
bool base_n_codec::isWhitespace(std::uint8_t c)
{
    switch(c)
    {
        case ' ':
        case '\r':
        case '\n':
        case '\t':
            return true;
        default:
            return false;
    }
}

base_n_codec::base_n_codec(size_t lineLength, std::vector<std::uint8_t> separator, std::uint8_t pad):
codec(),
_pad(pad),
_lineLength(separator.size()>0 ? lineLength : 0),
_separator(lineLength>0 ? separator : std::vector<std::uint8_t>())
{
}

void base_n_codec::addSeparator()
{
    _buffer.insert(_buffer.end(), _separator.begin(), _separator.end());
    _currentLinePos = 0;
}


//
// base64_codec
//
base64_codec::base64_codec(size_t lineLength, std::vector<std::uint8_t> separator, std::uint8_t pad):
base_n_codec(lineLength, separator, pad)
{
}


//
// base64_encoding
//

std::array<std::uint8_t, 64> base64_encoding::STANDARD_ENCODE_TABLE
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

std::array<std::uint8_t, 64> base64_encoding::URL_SAFE_ENCODE_TABLE
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

base64_encoding::base64_encoding(size_t lineLength, std::vector<std::uint8_t> separator):
base64_codec(lineLength, separator, PAD_DEFAULT),
_table(STANDARD_ENCODE_TABLE)
{
}

base64_encoding::base64_encoding(encoding_table& table, std::uint8_t pad, size_t lineLength, std::vector<std::uint8_t> separator):
base64_codec(lineLength, separator, pad),
_table(table)
{
}

base64_encoding::base64_encoding(bool urlSafe, size_t lineLength, std::vector<std::uint8_t> separator):
base64_codec(lineLength, separator, urlSafe ? 0 : PAD_DEFAULT),
_table(urlSafe ? URL_SAFE_ENCODE_TABLE : STANDARD_ENCODE_TABLE)
{
}

void base64_encoding::process(const std::uint8_t* buff, size_t len)
{
    for (size_t pos = 0; pos < len; pos++) {
        _state = (_state+1) % BYTES_PER_UNENCODED_BLOCK;
        _work = (_work << 8) + buff[pos];
        if (_state == 0) { // 3 bytes = 24 bits = 4 * 6 bits to extract
            _buffer.push_back(_table[(_work >> 18) & MASK_6BITS]);
            _buffer.push_back(_table[(_work >> 12) & MASK_6BITS]);
            _buffer.push_back(_table[(_work >> 6) & MASK_6BITS]);
            _buffer.push_back(_table[_work & MASK_6BITS]);
            _currentLinePos += BYTES_PER_ENCODED_BLOCK;
            if (_lineLength > 0 && _lineLength <= _currentLinePos) {
                addSeparator();
            }
        }
    }
}

void base64_encoding::finalize()
{
    base_n_codec::finalize();

    if (_state == 0 && _lineLength == 0) {
        return; // no leftovers to process and not using chunking
    }
    size_t savedPos = _buffer.size();

    switch(_state) // 0-2
    {
        case 0: // nothing to do here
            break;
        case 1: // 8 bits = 6 + 2
            // top 6 bits:
            _buffer.push_back(_table[(_work >> 2) & MASK_6BITS]);
            // remaining 2:
            _buffer.push_back(_table[(_work << 4) & MASK_6BITS]);
            // URL-SAFE skips the padding to further reduce size.
            if (_pad != 0) {
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
            }
            break;
        case 2 : // 16 bits = 6 + 6 + 4
            _buffer.push_back(_table[(_work >> 10) & MASK_6BITS]);
            _buffer.push_back(_table[(_work >> 4) & MASK_6BITS]);
            _buffer.push_back(_table[(_work << 2) & MASK_6BITS]);
            // URL-SAFE skips the padding to further reduce size.
            if (_pad != 0) {
                _buffer.push_back(_pad);
            }
            break;
        default:
            // Impossible !
            break;
    }

    _currentLinePos += _buffer.size() - savedPos; // keep track of current line position

    // if currentPos == 0 we are at the start of a line, so don't add CRLF
    if (_lineLength > 0 && _currentLinePos > 0) {
        addSeparator();
    }
}

//
// base64_encoding_input_stream
//
base64_encoding_input_stream::base64_encoding_input_stream(input_stream* stream):
codec_input_stream<base64_encoding>(stream)
{
}

base64_encoding_input_stream::base64_encoding_input_stream(input_stream* stream, size_t lineLength, std::vector<std::uint8_t> separator):
codec_input_stream<base64_encoding>(stream, lineLength, separator)
{
}

base64_encoding_input_stream::base64_encoding_input_stream(input_stream* stream, base64_codec::encoding_table& table, std::uint8_t pad, size_t lineLength, std::vector<std::uint8_t> separator):
codec_input_stream<base64_encoding>(stream, table, pad, lineLength, separator)
{
}

base64_encoding_input_stream::base64_encoding_input_stream(input_stream* stream, bool urlSafe, size_t lineLength, std::vector<std::uint8_t> separator):
codec_input_stream<base64_encoding>(stream, urlSafe, lineLength, separator)
{
}

//
// base64_encoding_output_stream
//
base64_encoding_output_stream::base64_encoding_output_stream(output_stream* stream):
codec_output_stream<base64_encoding>(stream)
{
}


base64_encoding_output_stream::base64_encoding_output_stream(output_stream* stream, size_t lineLength, std::vector<std::uint8_t> separator):
codec_output_stream<base64_encoding>(stream, lineLength, separator)
{
}

base64_encoding_output_stream::base64_encoding_output_stream(output_stream* stream, base64_codec::encoding_table& table, std::uint8_t pad, size_t lineLength, std::vector<std::uint8_t> separator):
codec_output_stream<base64_encoding>(stream, table, pad, lineLength, separator)
{
}

base64_encoding_output_stream::base64_encoding_output_stream(output_stream* stream, bool urlSafe, size_t lineLength, std::vector<std::uint8_t> separator):
codec_output_stream<base64_encoding>(stream, urlSafe, lineLength, separator)
{
}


//
// base64_decoding
//

base64_decoding::decoding_table base64_decoding::DECODE_TABLE
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63, 52, 53, 54,
    55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, -1, -1, -1, -1, 63, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

void base64_decoding::process(const std::uint8_t* buff, size_t len)
{
    for(size_t n = 0; n < len; ++n)
    {
        std::uint8_t b = buff[n];
        if (b == _pad) {
            // We're done.
            _eof = true;
            break;
        }
        else
        {
//            if (b < DECODE_TABLE.size()) {
                int8_t result = DECODE_TABLE[b];
                _state = (_state+1) % BYTES_PER_ENCODED_BLOCK;
                _work = (_work << BITS_PER_ENCODED_BYTE) + result;
                if (_state == 0) {
                    _buffer.push_back((_work >> 16) & MASK_8BITS);
                    _buffer.push_back((_work >> 8) & MASK_8BITS);
                    _buffer.push_back(_work & MASK_8BITS);
                }
//            }
        }
    }

    if(_eof)
    {
        switch (_state) {
            case 0 : // impossible, as excluded above
                // Do nothing
                break;
            case 1 : // 6 bits - ignore entirely
                // TODO not currently tested; perhaps it is impossible?
                break;
            case 2 : // 12 bits = 8 + 4
                _work = _work >> 4; // dump the extra 4 bits
                _buffer.push_back(_work & MASK_8BITS);
                break;
            case 3 : // 18 bits = 8 + 8 + 2
                _work = _work >> 2; // dump 2 bits
                _buffer.push_back((_work >> 8) & MASK_8BITS);
                _buffer.push_back((_work) & MASK_8BITS);
                break;
            default:
                // Impossible !
                break;
        }
    }
}

//
// base64_decoding_input_stream
//
base64_decoding_input_stream::base64_decoding_input_stream(input_stream* stream):
codec_input_stream<base64_decoding>(stream)
{
}

//
// base64_decoding_output_stream
//
base64_decoding_output_stream::base64_decoding_output_stream(output_stream* stream):
codec_output_stream<base64_decoding>(stream)
{
}







//
// base32_codec
//
base32_codec::base32_codec(size_t lineLength, std::vector<std::uint8_t> separator, std::uint8_t pad):
base_n_codec(lineLength, separator, pad)
{
}

//
// base32_encoding
//
base32_codec::encoding_table base32_encoding::STANDARD_ENCODE_TABLE =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '2', '3', '4', '5', '6', '7'
};

base32_codec::encoding_table base32_encoding::HEX_STANDARD_ENCODE_TABLE =
{
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
};

base32_encoding::base32_encoding(bool useHex, size_t lineLength, std::vector<std::uint8_t> separator, std::uint8_t pad):
base32_encoding(useHex?HEX_STANDARD_ENCODE_TABLE:STANDARD_ENCODE_TABLE, lineLength, separator, pad)
{
}

base32_encoding::base32_encoding(encoding_table& table, size_t lineLength, std::vector<std::uint8_t> separator, std::uint8_t pad):
base32_codec(lineLength, separator, pad),
_table(table)
{
}

void base32_encoding::process(const std::uint8_t* buff, size_t len)
{
    for (size_t pos = 0; pos < len; pos++) {
        _state = (_state+1) % BYTES_PER_UNENCODED_BLOCK;
        _work = (_work << 8) + buff[pos]; // BITS_PER_BYTE
        if (_state == 0) { // we have enough bytes to create our output
            _buffer.push_back( _table[(_work >> 35) & MASK_5BITS] );
            _buffer.push_back( _table[(_work >> 30) & MASK_5BITS] );
            _buffer.push_back( _table[(_work >> 25) & MASK_5BITS] );
            _buffer.push_back( _table[(_work >> 20) & MASK_5BITS] );
            _buffer.push_back( _table[(_work >> 15) & MASK_5BITS] );
            _buffer.push_back( _table[(_work >> 10) & MASK_5BITS] );
            _buffer.push_back( _table[(_work >> 5)  & MASK_5BITS] );
            _buffer.push_back( _table[ _work        & MASK_5BITS] );
            _work = 0;
            _currentLinePos += BYTES_PER_ENCODED_BLOCK;
            if (_lineLength > 0 && _lineLength <= _currentLinePos) {
                addSeparator();
            }
        }
    }
}

void base32_encoding::finalize()
{
    base_n_codec::finalize();
    if (_state == 0 && _lineLength == 0) {
        return; // no leftovers to process and not using chunking
    }
    size_t savedPos = _buffer.size();

    switch (_state) { // % 5 == 0 - 4
        case 0 :
            // nothing to do here
            break;
        case 1 : // Only 1 octet; take top 5 bits then remainder
            _buffer.push_back( _table[(_work >> 3) & MASK_5BITS] ); // 8-1*5 = 3
            _buffer.push_back( _table[(_work << 2) & MASK_5BITS] ); // 5-3=2
            if (_pad != 0) {
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
            }
            break;
        case 2 : // 2 octets = 16 bits to use
            _buffer.push_back( _table[(_work >> 11) & MASK_5BITS] ); // 16-1*5 = 11
            _buffer.push_back( _table[(_work >>  6) & MASK_5BITS] ); // 16-2*5 = 6
            _buffer.push_back( _table[(_work >>  1) & MASK_5BITS] ); // 16-3*5 = 1
            _buffer.push_back( _table[(_work <<  4) & MASK_5BITS] ); // 5-1 = 4
            if (_pad != 0) {
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
            }
            break;
        case 3 : // 3 octets = 24 bits to use
            _buffer.push_back( _table[(_work >> 19) & MASK_5BITS] ); // 24-1*5 = 19
            _buffer.push_back( _table[(_work >> 14) & MASK_5BITS] ); // 24-2*5 = 14
            _buffer.push_back( _table[(_work >>  9) & MASK_5BITS] ); // 24-3*5 = 9
            _buffer.push_back( _table[(_work >>  4) & MASK_5BITS] ); // 24-4*5 = 4
            _buffer.push_back( _table[(_work <<  1) & MASK_5BITS] ); // 5-4 = 1
            if (_pad != 0) {
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
                _buffer.push_back(_pad);
            }
            break;
        case 4 : // 4 octets = 32 bits to use
            _buffer.push_back( _table[(_work >> 27) & MASK_5BITS] ); // 32-1*5 = 27
            _buffer.push_back( _table[(_work >> 22) & MASK_5BITS] ); // 32-2*5 = 22
            _buffer.push_back( _table[(_work >> 17) & MASK_5BITS] ); // 32-3*5 = 17
            _buffer.push_back( _table[(_work >> 12) & MASK_5BITS] ); // 32-4*5 = 12
            _buffer.push_back( _table[(_work >>  7) & MASK_5BITS] ); // 32-5*5 =  7
            _buffer.push_back( _table[(_work >>  2) & MASK_5BITS] ); // 32-6*5 =  2
            _buffer.push_back( _table[(_work <<  3) & MASK_5BITS] ); // 5-2 = 3
            if (_pad != 0) {
                _buffer.push_back(_pad);
            }
            break;
        default:
            // Impossible !
            break;
    }

    _currentLinePos += _buffer.size() - savedPos; // keep track of current line position

    // if currentPos == 0 we are at the start of a line, so don't add CRLF
    if (_lineLength > 0 && _currentLinePos > 0) {
        addSeparator();
    }
}

//
// base32_encoding_input_stream
//
base32_encoding_input_stream::base32_encoding_input_stream(input_stream* stream):
codec_input_stream<base32_encoding>(stream)
{
}

base32_encoding_input_stream::base32_encoding_input_stream(input_stream* stream, base32_codec::encoding_table& table, size_t lineLength, std::vector<std::uint8_t> separator, std::uint8_t pad):
codec_input_stream<base32_encoding>(stream, table, lineLength, separator, pad)
{
}

base32_encoding_input_stream::base32_encoding_input_stream(input_stream* stream, bool useHex, size_t lineLength, std::vector<std::uint8_t> separator, std::uint8_t pad):
codec_input_stream<base32_encoding>(stream, useHex, lineLength, separator, pad)
{
}


//
// base32_encoding_output_stream
//
base32_encoding_output_stream::base32_encoding_output_stream(output_stream* stream):
codec_output_stream<base32_encoding>(stream)
{
}

base32_encoding_output_stream::base32_encoding_output_stream(output_stream* stream, base32_codec::encoding_table& table, size_t lineLength, std::vector<std::uint8_t> separator, std::uint8_t pad):
codec_output_stream<base32_encoding>(stream, table, lineLength, separator, pad)
{
}

base32_encoding_output_stream::base32_encoding_output_stream(output_stream* stream, bool useHex, size_t lineLength, std::vector<std::uint8_t> separator, std::uint8_t pad):
codec_output_stream<base32_encoding>(stream, useHex, lineLength, separator, pad)
{
}


//
// base32_decoding
//

base32_decoding::decoding_table base32_decoding::STANDARD_DECODE_TABLE
{
 //  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 00-0f
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 10-1f
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 20-2f
    -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, // 30-3f 2-7
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 40-4f A-N
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,                     // 50-5a O-Z
};

base32_decoding::decoding_table base32_decoding::HEX_STANDARD_DECODE_TABLE
{
 //  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 00-0f
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 10-1f
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 20-2f
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 30-3f 2-7
    -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, // 40-4f A-N
    25, 26, 27, 28, 29, 30, 31, 32,                                 // 50-57 O-V
};

base32_decoding::base32_decoding(bool useHex):
base32_decoding(useHex?HEX_STANDARD_DECODE_TABLE:STANDARD_DECODE_TABLE)
{
}

base32_decoding::base32_decoding(base32_codec::decoding_table& table):
base32_codec(),
_table(table)
{
}

void base32_decoding::process(const std::uint8_t* buff, size_t len)
{
    for(size_t n = 0; n < len; ++n)
    {
        std::uint8_t b = buff[n];
        if (b == _pad) {
            // We're done.
            _eof = true;
            break;
        }
        else
        {
            if (b < _table.size()) {
                int8_t result = _table[b];
                if (result >= 0) {
                    _state = (_state+1) % BYTES_PER_ENCODED_BLOCK;
                    _work = (_work << BITS_PER_ENCODED_BYTE) + result;
                    if (_state == 0) {
                        _buffer.push_back((_work >> 32) & MASK_8BITS);
                        _buffer.push_back((_work >> 24) & MASK_8BITS);
                        _buffer.push_back((_work >> 16) & MASK_8BITS);
                        _buffer.push_back((_work >> 8) & MASK_8BITS);
                        _buffer.push_back(_work & MASK_8BITS);
                    }
                }
            }
        }
    }

    // Two forms of EOF as far as Base32 decoder is concerned: actual
    // EOF (-1) and first time '=' character is encountered in stream.
    // This approach makes the '=' padding characters completely optional.
    if (_eof) { // if modulus < 2, nothing to do
        //  we ignore partial bytes, i.e. only multiples of 8 count
        switch (_state) {
            case 0 :
            case 1 :
                // Do nothing
                break;
            case 2 : // 10 bits, drop 2 and output one byte
                _buffer.push_back((_work >> 2) & MASK_8BITS);
                break;
            case 3 : // 15 bits, drop 7 and output 1 byte
                _buffer.push_back((_work >> 7) & MASK_8BITS);
                break;
            case 4 : // 20 bits = 2*8 + 4
                _work = _work >> 4; // drop 4 bits
                _buffer.push_back((_work >> 8) & MASK_8BITS);
                _buffer.push_back( _work       & MASK_8BITS);
                break;
            case 5 : // 25bits = 3*8 + 1
                _work = _work >> 1; // drop 1 bit
                _buffer.push_back((_work >> 16) & MASK_8BITS);
                _buffer.push_back((_work >>  8) & MASK_8BITS);
                _buffer.push_back( _work        & MASK_8BITS);
                break;
            case 6 : // 30bits = 3*8 + 6
                _work = _work >> 6; // drop 6 bits
                _buffer.push_back((_work >> 16) & MASK_8BITS);
                _buffer.push_back((_work >>  8) & MASK_8BITS);
                _buffer.push_back( _work        & MASK_8BITS);
                break;
            case 7 : // 35 = 4*8 +3
                _work = _work >> 3; // drop 3 bits
                _buffer.push_back((_work >> 24) & MASK_8BITS);
                _buffer.push_back((_work >> 16) & MASK_8BITS);
                _buffer.push_back((_work >>  8) & MASK_8BITS);
                _buffer.push_back( _work        & MASK_8BITS);
                break;
            default:
                // Impossible !
                break;
        }
    }
}

//
// base32_decoding_input_stream
//

base32_decoding_input_stream::base32_decoding_input_stream(input_stream* stream, bool useHex):
codec_input_stream<base32_decoding>(stream, useHex)
{
}

base32_decoding_input_stream::base32_decoding_input_stream(input_stream* stream, base32_codec::decoding_table& table):
codec_input_stream<base32_decoding>(stream, table)
{
}

//
// base32_decoding_output_stream
//
base32_decoding_output_stream::base32_decoding_output_stream(output_stream* stream, bool useHex):
codec_output_stream<base32_decoding>(stream, useHex)
{
}

base32_decoding_output_stream::base32_decoding_output_stream(output_stream* stream, base32_codec::decoding_table& table):
codec_output_stream<base32_decoding>(stream, table)
{
}







//
// base16_codec
//
base16_codec::base16_codec(size_t lineLength, std::vector<std::uint8_t> separator):
base_n_codec(lineLength, separator, 0)
{
}

//
// base16_encoding
//
base16_codec::encoding_table base16_encoding::UPPERCASE_ENCODE_TABLE
{
'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

base16_codec::encoding_table base16_encoding::LOWERCASE_ENCODE_TABLE
{
'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};


base16_encoding::base16_encoding(base16_codec::encoding_table& table, size_t lineLength, std::vector<std::uint8_t> separator):
base16_codec(lineLength, separator),
_table(table)
{
}

base16_encoding::base16_encoding(bool useUppercase, size_t lineLength, std::vector<std::uint8_t> separator):
base16_encoding(useUppercase?UPPERCASE_ENCODE_TABLE:LOWERCASE_ENCODE_TABLE, lineLength, separator)
{
}

void base16_encoding::process(const std::uint8_t* buff, size_t len)
{
    for (size_t pos = 0; pos < len; pos++) {
        _buffer.push_back( _table[(buff[pos] & 0xF0) >> 4 ] );
        _buffer.push_back( _table[(buff[pos] & 0x0F)      ] );

        _currentLinePos += BYTES_PER_ENCODED_BLOCK;
        if (_lineLength > 0 && _lineLength <= _currentLinePos) {
            addSeparator();
        }
    }
}

//
// base16_encoding_input_stream
//
base16_encoding_input_stream::base16_encoding_input_stream(input_stream* stream):
codec_input_stream<base16_encoding>(stream)
{
}

base16_encoding_input_stream::base16_encoding_input_stream(input_stream* stream, base16_codec::encoding_table& table, size_t lineLength, std::vector<std::uint8_t> separator):
codec_input_stream<base16_encoding>(stream, table, lineLength, separator)
{
}

base16_encoding_input_stream::base16_encoding_input_stream(input_stream* stream, bool useUppercase, size_t lineLength, std::vector<std::uint8_t> separator):
codec_input_stream<base16_encoding>(stream, useUppercase, lineLength, separator)
{
}

//
// base16_encoding_output_stream
//
base16_encoding_output_stream::base16_encoding_output_stream(output_stream* stream):
codec_output_stream<base16_encoding>(stream)
{
}

base16_encoding_output_stream::base16_encoding_output_stream(output_stream* stream, base16_codec::encoding_table& table, size_t lineLength, std::vector<std::uint8_t> separator):
codec_output_stream<base16_encoding>(stream, table, lineLength, separator)
{
}

base16_encoding_output_stream::base16_encoding_output_stream(output_stream* stream, bool useUppercase, size_t lineLength, std::vector<std::uint8_t> separator):
codec_output_stream<base16_encoding>(stream, useUppercase, lineLength, separator)
{
}

//
// base16_decoding
//
base16_codec::decoding_table base16_decoding::STANDARD_DECODE_TABLE
{
 //  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 00-0f
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 10-1f
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 20-2f
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 30-3f 0-9
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 40-4f A-F
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 50-5a
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 60-6f a-f
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 70-7f
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 80-8f
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 90-9f
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // A0-Af
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // B0-Bf
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // C0-Cf
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // D0-Df
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // E0-Ef
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  // F0-Ff
};

base16_decoding::base16_decoding():
base16_decoding(STANDARD_DECODE_TABLE)
{
}


base16_decoding::base16_decoding(base16_codec::decoding_table& table):
base16_codec(),
_table(table)
{
}

void base16_decoding::process(const std::uint8_t* buff, size_t len)
{
    for(size_t n = 0; n < len; ++n)
    {
        int8_t result = _table[buff[n]];
        if (result >= 0) {
            _work = (_work << BITS_PER_ENCODED_BYTE) + result;
            _state = (_state+1) % BYTES_PER_ENCODED_BLOCK;
            if (_state == 0) {
                _buffer.push_back(_work & MASK_8BITS);
            }
        }
    }
}



//
// base16_decoding_input_stream
//
base16_decoding_input_stream::base16_decoding_input_stream(input_stream* stream):
codec_input_stream<base16_decoding>(stream)
{
}

base16_decoding_input_stream::base16_decoding_input_stream(input_stream* stream, base16_codec::decoding_table& table):
codec_input_stream<base16_decoding>(stream, table)
{
}

//
// base16_decoding_output_stream
//
base16_decoding_output_stream::base16_decoding_output_stream(output_stream* stream):
codec_output_stream<base16_decoding>(stream)
{
}

base16_decoding_output_stream::base16_decoding_output_stream(output_stream* stream, base16_codec::decoding_table& table):
codec_output_stream<base16_decoding>(stream, table)
{
}






//
// base2_codec
//

std::array<uint8_t, 8> base2_codec::bits
{
    1, 2, 4, 8, 16, 32, 64, 128
};

base2_codec::base2_codec(size_t lineLength, std::vector<std::uint8_t> separator):
base_n_codec(lineLength, separator, 0)
{
}


//
// base2_encoding
//
base2_encoding::base2_encoding(size_t lineLength, std::vector<std::uint8_t> separator):
base2_codec(lineLength, separator)
{
}

void base2_encoding::process(const std::uint8_t* buff, size_t len)
{
    for (size_t pos = 0; pos < len; pos++) {
        _buffer.push_back( (buff[pos] & bits[7]) ? '1' : '0' );
        _buffer.push_back( (buff[pos] & bits[6]) ? '1' : '0' );
        _buffer.push_back( (buff[pos] & bits[5]) ? '1' : '0' );
        _buffer.push_back( (buff[pos] & bits[4]) ? '1' : '0' );
        _buffer.push_back( (buff[pos] & bits[3]) ? '1' : '0' );
        _buffer.push_back( (buff[pos] & bits[2]) ? '1' : '0' );
        _buffer.push_back( (buff[pos] & bits[1]) ? '1' : '0' );
        _buffer.push_back( (buff[pos] & bits[0]) ? '1' : '0' );

        _currentLinePos += BYTES_PER_ENCODED_BLOCK;
        if (_lineLength > 0 && _lineLength <= _currentLinePos) {
            addSeparator();
        }
    }
}

//
// base2_encoding_input_stream
//
base2_encoding_input_stream::base2_encoding_input_stream(input_stream* stream, size_t lineLength, std::vector<std::uint8_t> separator):
codec_input_stream<base2_encoding>(stream, lineLength, separator)
{
}

//
// base2_encoding_output_stream
//
base2_encoding_output_stream::base2_encoding_output_stream(output_stream* stream, size_t lineLength, std::vector<std::uint8_t> separator):
codec_output_stream<base2_encoding>(stream, lineLength, separator)
{
}

//
// base2_decoding
//
base2_decoding::base2_decoding():
base2_codec()
{
}

void base2_decoding::process(const std::uint8_t* buff, size_t len)
{
    for(size_t n = 0; n < len; ++n)
    {
        int8_t result = buff[n]=='0' ? 0 : 1;
        _work = (_work << BITS_PER_ENCODED_BYTE) + result;
        _state = (_state+1) % BYTES_PER_ENCODED_BLOCK;
        if (_state == 0) {
            _buffer.push_back(_work & MASK_8BITS);
        }
    }
}

//
// base2_decoding_input_stream
//
base2_decoding_input_stream::base2_decoding_input_stream(input_stream* stream):
codec_input_stream<base2_decoding>(stream)
{
}

//
// base2_decoding_output_stream
//
base2_decoding_output_stream::base2_decoding_output_stream(output_stream* stream):
codec_output_stream<base2_decoding>(stream)
{
}



//
// percent_encoding
//

percent_codec::encoding_table percent_encoding::ENCODE_TABLE
(
    "0000000000000000" // Fx
    "0000000000000000" // Ex
    "0000000000000000" // Dx
    "0000000000000000" // Cx
    "0000000000000000" // Bx
    "0000000000000000" // Ax
    "0000000000000000" // 9x
    "0000000000000000" // 8x
    "0000000000000000" // 7x
    "0000000000000000" // 6x
    "0010100000000000" // 5x
    "0000000000000001" // 4x
    "1010110000000000" // 3x
    "1001111111111010" // 2x
    "1111111111111111" // 1x
    "1111111111111111" // 0x


);

percent_encoding::percent_encoding():
percent_encoding(ENCODE_TABLE)
{
}

percent_encoding::percent_encoding(encoding_table& table):
percent_codec(),
_table(table)
{
}

void percent_encoding::process(const std::uint8_t* buff, size_t len)
{
    for (size_t pos = 0; pos < len; pos++) {
        uint8_t b = buff[pos];
        if (_table[b])
        {
            _buffer.push_back( '%' );
            _buffer.push_back( base16_encoding::UPPERCASE_ENCODE_TABLE[(b & 0xF0) >> 4 ] );
            _buffer.push_back( base16_encoding::UPPERCASE_ENCODE_TABLE[(b & 0x0F)      ] );
        }
        else
        {
            _buffer.push_back( b );
        }
    }
}

//
// percent_decoding
//
percent_decoding::percent_decoding():
percent_codec()
{
}

void percent_decoding::process(const std::uint8_t* buff, size_t len)
{
    for (size_t pos = 0; pos < len; pos++) {
        uint8_t b = buff[pos];
        switch (_state)
        {
            case 0:
                if (b == '%')
                {
                    _state++;
                }
                else
                {
                    _buffer.push_back( b );
                }
                break;
            case 1:
                _work = base16_decoding::STANDARD_DECODE_TABLE[b];
                _state++;
                break;
            case 2:
                _work = (_work << base16_codec::BITS_PER_ENCODED_BYTE) + base16_decoding::STANDARD_DECODE_TABLE[b];
                _buffer.push_back( _work );
                _state = 0;
                break;
            default:
                // Impossible !
                break;
        }
    }
}

//
// percent_encoding_output_stream
//
percent_encoding_input_stream::percent_encoding_input_stream(input_stream* stream):
codec_input_stream<percent_encoding>(stream)
{
}

percent_encoding_input_stream::percent_encoding_input_stream(input_stream* stream, percent_codec::encoding_table& table):
codec_input_stream<percent_encoding>(stream, table)
{
}

//
// percent_encoding_output_stream
//
percent_encoding_output_stream::percent_encoding_output_stream(output_stream* stream):
codec_output_stream<percent_encoding>(stream)
{
}

percent_encoding_output_stream::percent_encoding_output_stream(output_stream* stream, percent_codec::encoding_table& table):
codec_output_stream<percent_encoding>(stream, table)
{
}

//
// percent_decoding_input_stream
//
percent_decoding_input_stream::percent_decoding_input_stream(input_stream* stream):
codec_input_stream<percent_decoding>(stream)
{
}

//
// percent_decoding_output_stream
//
percent_decoding_output_stream::percent_decoding_output_stream(output_stream* stream):
codec_output_stream<percent_decoding>(stream)
{
}






//
// form_url_encoding
//
void form_url_encoding::process(const std::uint8_t* buff, size_t len)
{
    for (size_t pos = 0; pos < len; pos++) {
        uint8_t b = buff[pos];
        if (b == ' ')
        {
            _buffer.push_back( '+' );
        }
        else if (_table[b])
        {
            _buffer.push_back( '%' );
            _buffer.push_back( base16_encoding::UPPERCASE_ENCODE_TABLE[(b & 0xF0) >> 4 ] );
            _buffer.push_back( base16_encoding::UPPERCASE_ENCODE_TABLE[(b & 0x0F)      ] );
        }
        else
        {
            _buffer.push_back( b );
        }
    }
}

//
// form_url_decoding
//
void form_url_decoding::process(const std::uint8_t* buff, size_t len)
{
    for (size_t pos = 0; pos < len; pos++) {
        uint8_t b = buff[pos];
        switch (_state)
        {
            case 0:
                if (b == '%')
                {
                    _state++;
                }
                else if (b == '+')
                {
                    _buffer.push_back( ' ' );
                }
                else
                {
                    _buffer.push_back( b );
                }
                break;
            case 1:
                _work = base16_decoding::STANDARD_DECODE_TABLE[b];
                _state++;
                break;
            case 2:
                _work = (_work << base16_codec::BITS_PER_ENCODED_BYTE) + base16_decoding::STANDARD_DECODE_TABLE[b];
                _buffer.push_back( _work );
                _state = 0;
                break;
            default:
                // Impossible !
                break;
        }
    }
}


//
// form_url_encoding_input_stream
//
form_url_encoding_input_stream::form_url_encoding_input_stream(input_stream* stream):
codec_input_stream<form_url_encoding>(stream)
{
}


//
// form_url_encoding_output_stream
//
form_url_encoding_output_stream::form_url_encoding_output_stream(output_stream* stream):
codec_output_stream<form_url_encoding>(stream)
{
}


//
// form_url_decoding_input_stream
//
form_url_decoding_input_stream::form_url_decoding_input_stream(input_stream* stream):
codec_input_stream<form_url_decoding>(stream)
{
}

//
// percent_decoding_output_stream
//
form_url_decoding_output_stream::form_url_decoding_output_stream(output_stream* stream):
codec_output_stream<form_url_decoding>(stream)
{
}


}}} // namespace cxy::io::codec
