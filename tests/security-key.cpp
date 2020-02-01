/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/security-cipher.cpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include "security/key.hpp"


TEST_CASE( "Raw secret key", "[key]" ) {
    using namespace cxy;

    security::raw_secret_key key{0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34};

    REQUIRE( key.size() == 16);
}

/*
TEST_CASE( "Simple SHA1", "[md]" ) {
    using namespace cxy;

    auto md = security::message_digest::get("SHA1");

    auto res = md->update("The quick brown fox jumps", 25).update(" over the lazy dog", 18).digest();

    std::vector<uint8_t> val = {
        0x2f, 0xd4, 0xe1, 0xc6,     0x7a, 0x2d, 0x28, 0xfc,
        0xed, 0x84, 0x9e, 0xe1,     0xbb, 0x76, 0xe7, 0x39,
        0x1b, 0x93, 0xeb, 0x12
    };

    REQUIRE( res == val );
}
*/
