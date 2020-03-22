/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/security-signature.cpp
 * Copyright (C) 2020 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include "security/openssl.hpp"

#include <openssl/bn.h>

TEST_CASE( "Sign a buffer with RSA", "[RSA][Signature]" ) {

    using namespace cxy;
    using namespace cxy::security;

    constexpr size_t key_size = 2048 /* bits */;

    auto pair = rsa_key_pair::generator()->key_size(key_size).public_exponent(7ul).generate();
    REQUIRE( pair != nullptr);

    auto sign = cipher_builder().md("SHA-256").key(*pair->private_key()).sign();
    REQUIRE( sign != nullptr );

    auto verif = cipher_builder().md("SHA-256").key(*pair->public_key()).verify();
    REQUIRE( verif != nullptr );

    std::random_device r;
    std::default_random_engine e1(r());
    std::uniform_int_distribution<uint8_t> uniform_dist(0, 255);
    std::vector<uint8_t> sample;
    std::generate_n(std::back_inserter(sample), 64, [&](){return uniform_dist(e1);});

    auto signature = sign->update(sample.data(), sample.size()).sign();
    REQUIRE( signature.size() > 0 );

    verif->update(sample.data(), sample.size());
    REQUIRE( verif->verify(signature.data(), signature.size()) == true );


}
