/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/security-cipher.cpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include <algorithm>
#include <random>

#include "security/cipher.hpp"


TEST_CASE( "AES test", "[cipher]" ) {
    using namespace cxy;

    security::raw_secret_key key{0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34};

    std::vector<unsigned char> iv{0x42, 0x43, 0x44, 0x45, 0x5A, 0x5B, 0x5C, 0x5D, 0x60, 0x62, 0x64, 0x66, 0x8A, 0x9B, 0xAC, 0xBD};


    std::shared_ptr<security::cipher> enc = cxy::security::cipher_builder().algorithm(CXY_CIPHER_AES).mode(CXY_CIPHER_MODE_CBC).padding(CXY_CIPHER_PKCS7_PADDING).key(key).initial_vector(iv).encrypt();
    REQUIRE( enc != nullptr );

    std::shared_ptr<security::cipher> dec = cxy::security::cipher_builder().algorithm(CXY_CIPHER_AES).mode(CXY_CIPHER_MODE_CBC).padding(CXY_CIPHER_PKCS7_PADDING).key(key).initial_vector(iv).decrypt();
    REQUIRE( dec != nullptr );


    std::random_device r;
    std::default_random_engine e1(r());
    std::uniform_int_distribution<uint8_t> uniform_dist(0, 255);

    std::vector<uint8_t> sample;
    std::generate_n(std::back_inserter(sample), 4096, [&](){return uniform_dist(e1);});

    constexpr size_t count = 42;

    std::vector<uint8_t> res;

    // Encode
    std::vector<uint8_t> encoded;
    for(size_t i = 0; i < sample.size(); i += count) {
        size_t n = std::min(count, sample.size()-i);
        res = enc->update(&sample[i], n);
        encoded.insert(encoded.end(), res.begin(), res.end());
    }
    res = enc->finalize();
    encoded.insert(encoded.end(), res.begin(), res.end());

    // Decode
    std::vector<uint8_t> decoded;
    for(size_t i = 0; i < encoded.size(); i += count) {
        size_t n = std::min(count, encoded.size()-i);
        res = dec->update(&encoded[i], n);
        decoded.insert(decoded.end(), res.begin(), res.end());
    }
    res = dec->finalize();
    decoded.insert(decoded.end(), res.begin(), res.end());

    // Final test
    REQUIRE( sample == decoded );
}
