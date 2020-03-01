/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/io-codec.cpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include <random>
#include <list>

#include "io/codec.hpp"



//
// testInput
//

template<typename codec_t>
void test_input(const std::uint8_t* src, std::size_t srcsz, const std::uint8_t* tgt, std::size_t tgtsz)
{
	using namespace cxy;

    io::memory_input_stream mem(src, srcsz);
    codec_t codec(&mem);
    io::memory_output_stream res;
    codec.write_to(&res);
    mem.close();

#if 0 // MANUAL DEBUG ONLY
std::cout << "Checking encoding '";
for(size_t n=0; n<srcsz; ++n) std::cout << (char)src[n];
std::cout << "' result is '";
for(size_t n=0; n<res.size(); ++n) std::cout << (char)res.data()[n];
std::cout << "' and should be '";
for(size_t n=0; n<tgtsz; ++n) std::cout << (char)tgt[n];
std::cout << "'" << std::endl;
#endif // 0 // MANUAL DEBUG ONLY

    REQUIRE( std::equal(tgt, tgt+tgtsz, res.data(), res.data()+res.size()) );
}


template<class codec_t>
void test_input(const std::string& src, const std::string& tgt)
{
    test_input<codec_t>((const std::uint8_t*)src.data(), src.size(), (const std::uint8_t*)tgt.data(), tgt.size());
}

template<class codec_t>
void test_input(const std::vector<std::uint8_t>& src, const std::vector<std::uint8_t>& tgt)
{
    test_input<codec_t>(src.data(), src.size(), tgt.data(), tgt.size());
}

//
// testOutput
//

template<class codec_t>
void test_output(const std::uint8_t* src, std::size_t srcsz, const std::uint8_t* tgt, std::size_t tgtsz)
{
	using namespace cxy;
    io::memory_input_stream mem(src, srcsz);
    io::memory_output_stream res;
    codec_t codec(&res);
    mem.write_to(&codec);
    mem.close();

	REQUIRE( std::equal(tgt, tgt+tgtsz, res.data(), res.data()+res.size()) );

}

template<class codec_t>
void test_output(const std::string& src, const std::string& tgt)
{
    test_output<codec_t>((const std::uint8_t*)src.data(), src.size(), (const std::uint8_t*)tgt.data(), tgt.size());
}

template<class codec_t>
void test_output(const std::vector<std::uint8_t>& src, const std::vector<std::uint8_t>& tgt)
{
    test_output<codec_t>(src.data(), src.size(), tgt.data(), tgt.size());
}


//
// Tests:
//


TEST_CASE( "Base64 encoding input stream", "[io]" ) {
    using namespace cxy;

    test_input<io::codec::base64_encoding_input_stream>("", "");
    test_input<io::codec::base64_encoding_input_stream>("f", "Zg==");
    test_input<io::codec::base64_encoding_input_stream>("fo", "Zm8=");
    test_input<io::codec::base64_encoding_input_stream>("foo", "Zm9v");
    test_input<io::codec::base64_encoding_input_stream>("foob", "Zm9vYg==");
    test_input<io::codec::base64_encoding_input_stream>("fooba", "Zm9vYmE=");
    test_input<io::codec::base64_encoding_input_stream>("foobar", "Zm9vYmFy");
}


TEST_CASE( "Base64 encoding output stream", "[io]" ) {
    using namespace cxy;

    test_output<io::codec::base64_encoding_output_stream>("", "");
    test_output<io::codec::base64_encoding_output_stream>("f", "Zg==");
    test_output<io::codec::base64_encoding_output_stream>("fo", "Zm8=");
    test_output<io::codec::base64_encoding_output_stream>("foo", "Zm9v");
    test_output<io::codec::base64_encoding_output_stream>("foob", "Zm9vYg==");
    test_output<io::codec::base64_encoding_output_stream>("fooba", "Zm9vYmE=");
    test_output<io::codec::base64_encoding_output_stream>("foobar", "Zm9vYmFy");
}


TEST_CASE( "Base64 decoding input stream", "[io]" ) {
    using namespace cxy;

    test_input<io::codec::base64_decoding_input_stream>("", "");
    test_input<io::codec::base64_decoding_input_stream>("Zg==", "f");
    test_input<io::codec::base64_decoding_input_stream>("Zm8=", "fo");
    test_input<io::codec::base64_decoding_input_stream>("Zm9v", "foo");
    test_input<io::codec::base64_decoding_input_stream>("Zm9vYg==", "foob");
    test_input<io::codec::base64_decoding_input_stream>("Zm9vYmE=", "fooba");
    test_input<io::codec::base64_decoding_input_stream>("Zm9vYmFy", "foobar");
}


TEST_CASE( "Base64 decoding output stream", "[io]" ) {
    using namespace cxy;

    test_output<io::codec::base64_decoding_output_stream>("", "");
    test_output<io::codec::base64_decoding_output_stream>("Zg==", "f");
    test_output<io::codec::base64_decoding_output_stream>("Zm8=", "fo");
    test_output<io::codec::base64_decoding_output_stream>("Zm9v", "foo");
    test_output<io::codec::base64_decoding_output_stream>("Zm9vYg==", "foob");
    test_output<io::codec::base64_decoding_output_stream>("Zm9vYmE=", "fooba");
    test_output<io::codec::base64_decoding_output_stream>("Zm9vYmFy", "foobar");
}




TEST_CASE( "Base32 encoding input stream", "[io]" ) {
    using namespace cxy;

    test_input<io::codec::base32_encoding_input_stream>("", "");
    test_input<io::codec::base32_encoding_input_stream>("f", "MY======");
    test_input<io::codec::base32_encoding_input_stream>("fo", "MZXQ====");
    test_input<io::codec::base32_encoding_input_stream>("foo", "MZXW6===");
    test_input<io::codec::base32_encoding_input_stream>("foob", "MZXW6YQ=");
    test_input<io::codec::base32_encoding_input_stream>("fooba", "MZXW6YTB");
    test_input<io::codec::base32_encoding_input_stream>("foobar", "MZXW6YTBOI======");
}


TEST_CASE( "Base32 encoding output stream", "[io]" ) {
    using namespace cxy;

    test_output<io::codec::base32_encoding_output_stream>("", "");
    test_output<io::codec::base32_encoding_output_stream>("f", "MY======");
    test_output<io::codec::base32_encoding_output_stream>("fo", "MZXQ====");
    test_output<io::codec::base32_encoding_output_stream>("foo", "MZXW6===");
    test_output<io::codec::base32_encoding_output_stream>("foob", "MZXW6YQ=");
    test_output<io::codec::base32_encoding_output_stream>("fooba", "MZXW6YTB");
    test_output<io::codec::base32_encoding_output_stream>("foobar", "MZXW6YTBOI======");
}


TEST_CASE( "Base32 decoding input stream", "[io]" ) {
    using namespace cxy;

    test_input<io::codec::base32_decoding_input_stream>("", "");
    test_input<io::codec::base32_decoding_input_stream>("MY======", "f");
    test_input<io::codec::base32_decoding_input_stream>("MZXQ====", "fo");
    test_input<io::codec::base32_decoding_input_stream>("MZXW6===", "foo");
    test_input<io::codec::base32_decoding_input_stream>("MZXW6YQ=", "foob");
    test_input<io::codec::base32_decoding_input_stream>("MZXW6YTB", "fooba");
    test_input<io::codec::base32_decoding_input_stream>("MZXW6YTBOI======", "foobar");
}


TEST_CASE( "Base32 decoding output stream", "[io]" ) {
    using namespace cxy;

    test_output<io::codec::base32_decoding_output_stream>("", "");
    test_output<io::codec::base32_decoding_output_stream>("MY======", "f");
    test_output<io::codec::base32_decoding_output_stream>("MZXQ====", "fo");
    test_output<io::codec::base32_decoding_output_stream>("MZXW6===", "foo");
    test_output<io::codec::base32_decoding_output_stream>("MZXW6YQ=", "foob");
    test_output<io::codec::base32_decoding_output_stream>("MZXW6YTB", "fooba");
    test_output<io::codec::base32_decoding_output_stream>("MZXW6YTBOI======", "foobar");
}




TEST_CASE( "Base16 encoding input stream", "[io]" ) {
    using namespace cxy;

    test_input<io::codec::base16_encoding_input_stream>("", "");
    test_input<io::codec::base16_encoding_input_stream>("f", "66");
    test_input<io::codec::base16_encoding_input_stream>("fo", "666F");
    test_input<io::codec::base16_encoding_input_stream>("foo", "666F6F");
    test_input<io::codec::base16_encoding_input_stream>("foob", "666F6F62");
    test_input<io::codec::base16_encoding_input_stream>("fooba", "666F6F6261");
    test_input<io::codec::base16_encoding_input_stream>("foobar", "666F6F626172");
}


TEST_CASE( "Base16 encoding output stream", "[io]" ) {
    using namespace cxy;

    test_output<io::codec::base16_encoding_output_stream>("", "");
    test_output<io::codec::base16_encoding_output_stream>("f", "66");
    test_output<io::codec::base16_encoding_output_stream>("fo", "666F");
    test_output<io::codec::base16_encoding_output_stream>("foo", "666F6F");
    test_output<io::codec::base16_encoding_output_stream>("foob", "666F6F62");
    test_output<io::codec::base16_encoding_output_stream>("fooba", "666F6F6261");
    test_output<io::codec::base16_encoding_output_stream>("foobar", "666F6F626172");
}


TEST_CASE( "Base16 decoding input stream", "[io]" ) {
    using namespace cxy;

    test_input<io::codec::base16_decoding_input_stream>("", "");
    test_input<io::codec::base16_decoding_input_stream>("66", "f");
    test_input<io::codec::base16_decoding_input_stream>("666F", "fo");
    test_input<io::codec::base16_decoding_input_stream>("666F6F", "foo");
    test_input<io::codec::base16_decoding_input_stream>("666F6F62", "foob");
    test_input<io::codec::base16_decoding_input_stream>("666F6F6261", "fooba");
    test_input<io::codec::base16_decoding_input_stream>("666F6F626172", "foobar");
}


TEST_CASE( "Base16 decoding output stream", "[io]" ) {
    using namespace cxy;

    test_output<io::codec::base16_decoding_output_stream>("", "");
    test_output<io::codec::base16_decoding_output_stream>("66", "f");
    test_output<io::codec::base16_decoding_output_stream>("666F", "fo");
    test_output<io::codec::base16_decoding_output_stream>("666F6F", "foo");
    test_output<io::codec::base16_decoding_output_stream>("666F6F62", "foob");
    test_output<io::codec::base16_decoding_output_stream>("666F6F6261", "fooba");
    test_output<io::codec::base16_decoding_output_stream>("666F6F626172", "foobar");
}






TEST_CASE( "Base2 encoding input stream", "[io]" ) {
    using namespace cxy;

    test_input<io::codec::base2_encoding_input_stream>("", "");
    test_input<io::codec::base2_encoding_input_stream>("f", "01100110");
    test_input<io::codec::base2_encoding_input_stream>("fo", "0110011001101111");
    test_input<io::codec::base2_encoding_input_stream>("foo", "011001100110111101101111");
    test_input<io::codec::base2_encoding_input_stream>("foob", "01100110011011110110111101100010");
    test_input<io::codec::base2_encoding_input_stream>("fooba", "0110011001101111011011110110001001100001");
    test_input<io::codec::base2_encoding_input_stream>("foobar", "011001100110111101101111011000100110000101110010");
}


TEST_CASE( "Base2 encoding output stream", "[io]" ) {
    using namespace cxy;

    test_output<io::codec::base2_encoding_output_stream>("", "");
    test_output<io::codec::base2_encoding_output_stream>("f", "01100110");
    test_output<io::codec::base2_encoding_output_stream>("fo", "0110011001101111");
    test_output<io::codec::base2_encoding_output_stream>("foo", "011001100110111101101111");
    test_output<io::codec::base2_encoding_output_stream>("foob", "01100110011011110110111101100010");
    test_output<io::codec::base2_encoding_output_stream>("fooba", "0110011001101111011011110110001001100001");
    test_output<io::codec::base2_encoding_output_stream>("foobar", "011001100110111101101111011000100110000101110010");
}




TEST_CASE( "Base2 decoding input stream", "[io]" ) {
    using namespace cxy;

    test_input<io::codec::base2_decoding_input_stream>("", "");
    test_input<io::codec::base2_decoding_input_stream>("01100110", "f");
    test_input<io::codec::base2_decoding_input_stream>("0110011001101111", "fo");
    test_input<io::codec::base2_decoding_input_stream>("011001100110111101101111", "foo");
    test_input<io::codec::base2_decoding_input_stream>("01100110011011110110111101100010", "foob");
    test_input<io::codec::base2_decoding_input_stream>("0110011001101111011011110110001001100001", "fooba");
    test_input<io::codec::base2_decoding_input_stream>("011001100110111101101111011000100110000101110010", "foobar");
}


TEST_CASE( "Base2 decoding output stream", "[io]" ) {
    using namespace cxy;

    test_output<io::codec::base2_decoding_output_stream>("", "");
    test_output<io::codec::base2_decoding_output_stream>("01100110", "f");
    test_output<io::codec::base2_decoding_output_stream>("0110011001101111", "fo");
    test_output<io::codec::base2_decoding_output_stream>("011001100110111101101111", "foo");
    test_output<io::codec::base2_decoding_output_stream>("01100110011011110110111101100010", "foob");
    test_output<io::codec::base2_decoding_output_stream>("0110011001101111011011110110001001100001", "fooba");
    test_output<io::codec::base2_decoding_output_stream>("011001100110111101101111011000100110000101110010", "foobar");
}


TEST_CASE( "Percent encoding codec", "[io]" ) {
    using namespace cxy;

    test_input<io::codec::percent_encoding_input_stream>("", "");
    test_input<io::codec::percent_encoding_input_stream>("foo %/bar", "foo %25%2Fbar");

    test_output<io::codec::percent_encoding_output_stream>("", "");
    test_output<io::codec::percent_encoding_output_stream>("foo %/bar", "foo %25%2Fbar");

    test_input<io::codec::percent_decoding_input_stream>("", "");
    test_input<io::codec::percent_decoding_input_stream>("foo %25%2Fbar", "foo %/bar");

    test_output<io::codec::percent_decoding_output_stream>("", "");
    test_output<io::codec::percent_decoding_output_stream>("foo %25%2Fbar", "foo %/bar");
}


TEST_CASE( "formurl encoding codec", "[io]" ) {
    using namespace cxy;

    test_input<io::codec::form_url_encoding_input_stream>("", "");
    test_input<io::codec::form_url_encoding_input_stream>("foo %/bar+", "foo+%25%2Fbar%2B");

	test_output<io::codec::form_url_encoding_output_stream>("", "");
    test_output<io::codec::form_url_encoding_output_stream>("foo %/bar+", "foo+%25%2Fbar%2B");

    test_input<io::codec::form_url_decoding_input_stream>("", "");
    test_input<io::codec::form_url_decoding_input_stream>("foo+%25%2Fbar%2B", "foo %/bar+");

    test_output<io::codec::form_url_decoding_output_stream>("", "");
    test_output<io::codec::form_url_decoding_output_stream>("foo+%25%2Fbar%2B", "foo %/bar+");
}
