/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/security-cipher.cpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include <algorithm>
#include <random>

#include "security/cipher.hpp"


TEST_CASE( "AES test", "[cipher][AES]" ) {
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

TEST_CASE( "RSA sipher test", "[cipher][RSA]" ) {
    using namespace cxy;

    constexpr size_t key_size = 2048 /* bits */;

    auto pair = security::rsa_key_pair::generator()->key_size(key_size).public_exponent(7ul).generate();
    REQUIRE( pair != nullptr);
    auto rsapair = std::dynamic_pointer_cast<security::rsa_key_pair>(pair);
    REQUIRE( rsapair != nullptr);

    auto pub = rsapair->rsa_public_key();
    REQUIRE( pub != nullptr);
    auto priv = rsapair->rsa_private_key();
    REQUIRE( priv != nullptr);

    std::random_device r;
    std::default_random_engine e1(r());
    std::uniform_int_distribution<uint8_t> uniform_dist(0, 255);

    std::shared_ptr<security::cipher> enc, dec;
    std::vector<uint8_t> sample;

    SECTION( "No padding: data size shall equals to key size" ) {
        std::generate_n(std::back_inserter(sample), key_size/8, [&](){return uniform_dist(e1);});
        enc = cxy::security::cipher_builder().key(*pub).padding(CXY_CIPHER_NO_PADDING).encrypt();
        dec = cxy::security::cipher_builder().key(*priv).padding(CXY_CIPHER_NO_PADDING).decrypt();
    }

    SECTION( "PKCS1 padding: data size shall be less or equals to key size - 11" ) {
        std::generate_n(std::back_inserter(sample), key_size/8 - 11 , [&](){return uniform_dist(e1);});
        enc = cxy::security::cipher_builder().key(*pub).padding(CXY_CIPHER_PKCS1_PADDING).encrypt();
        dec = cxy::security::cipher_builder().key(*priv).padding(CXY_CIPHER_PKCS1_PADDING).decrypt();
    }

    SECTION( "OAEP padding: data size shall be less or equals to key size - 42" ) {
        std::generate_n(std::back_inserter(sample), key_size/8 - 42 , [&](){return uniform_dist(e1);});
        enc = cxy::security::cipher_builder().key(*pub).padding(CXY_CIPHER_PKCS1_OAEP_PADDING).encrypt();
        dec = cxy::security::cipher_builder().key(*priv).padding(CXY_CIPHER_PKCS1_OAEP_PADDING).decrypt();
    }


    REQUIRE( enc != nullptr );
    REQUIRE( dec != nullptr );

    std::vector<uint8_t> encoded = enc->finalize(sample.data(), sample.size() );
    REQUIRE( encoded.size() > 0 );

    std::vector<uint8_t> res = dec->finalize(encoded.data(), encoded.size() );
    REQUIRE( res == sample );


}
