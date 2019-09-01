/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/io-stream.cpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include <random>
#include <list>

#include "io/stream.hpp"


TEST_CASE( "Memory input stream", "[io]" ) {
    using namespace cxy;

    std::uint8_t arr[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    io::memory_input_stream stm(arr, 10);

    // Initailly available
    REQUIRE(stm.available() == 10 );

    // First read byte
    REQUIRE(stm.read() == 0 );
    // Remaining available after first reading
    REQUIRE(stm.available() == 9);

    // Second read size
    std::uint8_t res[4];
    REQUIRE( stm.read(res, 4) == 4);
    REQUIRE( res[0] == arr[1] );
    REQUIRE( res[1] == arr[2] );
    REQUIRE( res[2] == arr[3] );
    REQUIRE( res[3] == arr[4] );
    // Remaining available after second reading
    REQUIRE( stm.available() == 5 );

    // Third read size
    std::uint8_t res2[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    REQUIRE( stm.read(res2, 10) == 5 );
    REQUIRE( res2[0]==arr[5] );
    REQUIRE( res2[1]==arr[6] );
    REQUIRE( res2[2]==arr[7] );
    REQUIRE( res2[3]==arr[8] );
    REQUIRE( res2[4]==arr[9] );
    REQUIRE( res2[5]==0 );
    REQUIRE( res2[6]==0 );
    // Remaining available after third reading
    REQUIRE(stm.available()==0 );

    // Fourth read byte
    REQUIRE(stm.read()==-1 );
    // Remaining available after fourth reading
    REQUIRE(stm.available()==0 );

    std::uint8_t res3[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // Fifth read size
    REQUIRE( stm.read(res3, 10)==-1 );
    // Fifth read size, byte 0
    REQUIRE( res3[0]==0 );
}


TEST_CASE( "Write to", "[io]" ) {
    using namespace cxy;

    std::vector<std::uint8_t> arr;

    std::random_device rd;
    std::default_random_engine e1(rd());
    std::uniform_int_distribution<std::uint8_t> uniform_dist(0, 255);

    for(size_t n=0; n<12345; ++n)
    {
        arr.push_back(uniform_dist(e1));
    }

    io::memory_input_stream stm(arr.data(), arr.size());
    io::memory_output_stream mem;
    stm.write_to(&mem);


    REQUIRE( mem.size()==arr.size() );
    REQUIRE( mem.to<std::vector<uint8_t>>() == arr );
}

TEST_CASE( "Data input stream", "[io]" ) {
    using namespace cxy;

    std::uint8_t src[] { 25, 0x18, 0x18, 0x4A, 0x4A, 0x4A, 0x4A, 0, 0x2F, 0};
    io::memory_input_stream mem(src, 10);
    io::data_input_stream data(&mem);

    // Remaining available
    REQUIRE( data.available()==sizeof(src) );

    std::uint8_t uint8 = data.read<std::uint8_t>();
    REQUIRE( uint8==src[0] );

    std::int16_t int16 = data.read<std::int16_t>();
    REQUIRE( int16==0x1818 );

    std::uint32_t uint32 = data.read<std::uint32_t>();
    REQUIRE( uint32==0x4A4A4A4A );

    bool b = data.read<bool>();
    REQUIRE( b == false );
    b = data.read<bool>();
    REQUIRE( b == true );

}


TEST_CASE( "Data output stream", "[io]" ) {
    using namespace cxy;

    std::vector<std::uint8_t> src { 25, 0x18, 0x18, 0x4A, 0x4A, 0x4A, 0x4A, 0, 0xFF};

    io::memory_output_stream mem;
    io::data_output_stream data(&mem);

    data.write<std::uint8_t>(25);
    data.write<std::int16_t>(0x1818);
    data.write<std::uint32_t>(0x4A4A4A4A);
    data.write<bool>(false);
    data.write<bool>(true);

    REQUIRE( src==mem.to<std::vector<std::uint8_t>>() );

}
