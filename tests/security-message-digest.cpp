/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/security-message-digest.cpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include "security/message-digest.hpp"


TEST_CASE( "Empty SHA1", "[md]" ) {
    using namespace cxy;

    auto md = security::message_digest::get("SHA1");

    REQUIRE( md != nullptr );
    REQUIRE( md->digest_length() == 20 );

    auto res = md->digest();

    REQUIRE( res.size() == md->digest_length() );

    std::vector<uint8_t> val = {
        0xda, 0x39, 0xa3, 0xee,     0x5e, 0x6b, 0x4b, 0x0d,
        0x32, 0x55, 0xbf, 0xef,     0x95, 0x60, 0x18, 0x90,
        0xaf, 0xd8, 0x07, 0x09
    };

    REQUIRE( res == val );
}


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
