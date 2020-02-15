/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/security-cipher.cpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include "security/key.hpp"

#include "security/openssl.hpp"

#include <openssl/bn.h>

TEST_CASE( "Convert OpenSSL BN to big_integer" ) {

    BIGNUM* bn = BN_new();
    cxy::math::big_integer bi;

    unsigned long l = 12345678l;

    BN_set_word(bn, l);

    bi = cxy::security::openssl::bn2bi(bn);

    BN_clear_free(bn);

    REQUIRE( bi == l);
}

TEST_CASE( "Convert big_integer to OpenSSL BN" ) {

    BIGNUM* bn = BN_new();
    cxy::math::big_integer bi;

    unsigned long l = 12345678l;

    bi = l;

    cxy::security::openssl::bi2bn(bi, bn);

    unsigned long res = BN_get_word(bn);

    BN_clear_free(bn);

    REQUIRE( res == l);
}


TEST_CASE( "Raw secret key", "[key]" ) {
    using namespace cxy;

    security::raw_secret_key key{0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34};

    REQUIRE( key.size() == 16);
}


TEST_CASE( "RSA gen keys", "[key][rsa]" ) {
    using namespace cxy;

    auto pair = security::rsa_key_pair::generator()->key_size(2048).public_exponent(7ul).generate();
    REQUIRE( pair != nullptr);
    auto rsapair = std::dynamic_pointer_cast<security::rsa_key_pair>(pair);
    REQUIRE( rsapair != nullptr);

    auto pub = rsapair->rsa_public_key();
    REQUIRE( pub != nullptr);
    REQUIRE( pub->public_exponent() != 0l );

    auto priv = rsapair->rsa_private_key();
    REQUIRE( priv != nullptr);
    REQUIRE( priv->private_exponent() != 0l );

    REQUIRE( pub->modulus() == priv->modulus() );
}
