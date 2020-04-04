/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/security-pem.cpp
 * Copyright (C) 2020 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include "security/openssl.hpp"

#include <iostream>
#include <cstring>


TEST_CASE( "PEM RSA-dedicated key writer/reader to/from string", "[PEM][RSA][PKCS#1]" ) {
    using namespace cxy::security;

    auto pair = rsa_key_pair::generator()->key_size(2048).public_exponent(7ul).generate();
    REQUIRE( pair != nullptr);
    auto rsapair = std::dynamic_pointer_cast<rsa_key_pair>(pair);
    REQUIRE( rsapair != nullptr);

    auto pub = rsapair->rsa_public_key();
    REQUIRE( pub != nullptr);

    auto priv = rsapair->rsa_private_key();
    REQUIRE( priv != nullptr);

    SECTION("Write then read PKCS#1 public RSA key")
    {
        openssl::ossl_string_pem_writer writer;

        writer.rsa_public_key(*pub);

        std::string str = writer.str();
        REQUIRE( str.length() > 0 );

        openssl::ossl_string_pem_reader reader(str);

        auto pubkey = reader.rsa_public_key();
        REQUIRE( pubkey != nullptr );

        REQUIRE( pubkey->modulus() == pub->modulus() );
        REQUIRE( pubkey->public_exponent() == pub->public_exponent() );
    }

    SECTION("Write then read PKCS#1 private RSA key")
    {
        openssl::ossl_string_pem_writer writer;

        writer.rsa_private_key(*priv);

        std::string str = writer.str();
        REQUIRE( str.length() > 0 );

        openssl::ossl_string_pem_reader reader(str);

        auto privkey = reader.rsa_private_key();
        REQUIRE( privkey != nullptr );

        REQUIRE( privkey->modulus() == priv->modulus() );
        REQUIRE( privkey->private_exponent() == priv->private_exponent() );
    }

    SECTION("Write then read PKCS#1 encrypted private RSA key")
    {
        static const std::string password = "tititoto";

        openssl::ossl_string_pem_writer writer;

        writer.rsa_private_key(*priv, cipher_builder{}.algorithm("AES").mode("CBC"), password);

        std::string str = writer.str();
        REQUIRE( str.length() > 0 );

        openssl::ossl_string_pem_reader reader(str);

        auto privkey = reader.rsa_private_key(password);
        REQUIRE( privkey != nullptr );

        REQUIRE( privkey->modulus() == priv->modulus() );
        REQUIRE( privkey->private_exponent() == priv->private_exponent() );
    }

}


TEST_CASE( "PEM generic key writer/reader to/from string", "[PEM][RSA][PKCS#8]" ) {
    using namespace cxy::security;

    auto pair = rsa_key_pair::generator()->key_size(2048).public_exponent(7ul).generate();
    REQUIRE( pair != nullptr);
    auto rsapair = std::dynamic_pointer_cast<rsa_key_pair>(pair);
    REQUIRE( rsapair != nullptr);

    auto pub = rsapair->rsa_public_key();
    REQUIRE( pub != nullptr);

    auto priv = rsapair->rsa_private_key();
    REQUIRE( priv != nullptr);

    SECTION("Write then read PKCS#8 public RSA key")
    {
        openssl::ossl_string_pem_writer writer;

        writer.public_key(*pub);

        std::string str = writer.str();
        REQUIRE( str.length() > 0 );

        openssl::ossl_string_pem_reader reader(str);

        auto pubkey = reader.public_key();
        REQUIRE( pubkey != nullptr );

        auto rsapubkey = std::dynamic_pointer_cast<rsa_public_key>(pubkey);
        REQUIRE( rsapubkey != nullptr );

        REQUIRE( rsapubkey->modulus() == pub->modulus() );
        REQUIRE( rsapubkey->public_exponent() == pub->public_exponent() );
    }

    SECTION("Write then read PKCS#8 private RSA key")
    {
        openssl::ossl_string_pem_writer writer;

        writer.private_key(*priv);

        std::string str = writer.str();
        REQUIRE( str.length() > 0 );

        openssl::ossl_string_pem_reader reader(str);

        auto privkey = reader.private_key();
        REQUIRE( privkey != nullptr );

        auto rsaprivkey = std::dynamic_pointer_cast<rsa_private_key>(privkey);
        REQUIRE( rsaprivkey != nullptr );

        REQUIRE( rsaprivkey->modulus() == priv->modulus() );
        REQUIRE( rsaprivkey->private_exponent() == priv->private_exponent() );
    }

    SECTION("Write then read PKCS#8 encrypted private RSA key")
    {
        static const std::string password = "tititoto";

        openssl::ossl_string_pem_writer writer;

        writer.rsa_private_key(*priv, cipher_builder{}.algorithm("AES").mode("CBC"), password);

        std::string str = writer.str();
        REQUIRE( str.length() > 0 );

        openssl::ossl_string_pem_reader reader(str);

        auto privkey = reader.rsa_private_key(password);
        REQUIRE( privkey != nullptr );

        auto rsaprivkey = std::dynamic_pointer_cast<rsa_private_key>(privkey);
        REQUIRE( rsaprivkey != nullptr );

        REQUIRE( rsaprivkey->modulus() == priv->modulus() );
        REQUIRE( rsaprivkey->private_exponent() == priv->private_exponent() );
    }

}


