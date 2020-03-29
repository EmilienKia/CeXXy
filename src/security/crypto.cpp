/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/crypto.cpp
 * Copyright (C) 2019-2020 Emilien Kia <emilien.kia+dev@gmail.com>
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

#include "crypto.hpp"
#include "openssl.hpp"


namespace cxy
{
namespace security
{


//
// RSA key pair generation
//

const cxy::math::big_integer rsa_key_pair_generator::F0{3ul};

const cxy::math::big_integer rsa_key_pair_generator::F4{65537ul};

std::string rsa_key_pair_generator::algorithm() const {
    return "RSA";
}

std::shared_ptr<rsa_key_pair_generator> rsa_key_pair::generator()
{
    return std::dynamic_pointer_cast<rsa_key_pair_generator>(
        std::make_shared<openssl::ossl_rsa_key_pair_generator>()
    );
}


//
// cipher_builder
//

cipher_builder& cipher_builder::algorithm(const std::string& algo)
{
    _algo = algo;
    return *this;
}

cipher_builder& cipher_builder::mode(const std::string& mode)
{
    _mode = mode;
    return *this;

}

cipher_builder& cipher_builder::padding(const std::string& padding)
{
    _pad = padding;
    return *this;
}

cipher_builder& cipher_builder::md(const std::string& md)
{
    _md = md;
    return *this;
}

cipher_builder& cipher_builder::key(cxy::security::key& key)
{
    _key = &key;
    return *this;

}

cipher_builder& cipher_builder::initial_vector(const std::vector<uint8_t/*std::byste*/> iv)
{
    _iv = iv;
    return *this;
}

const std::string& cipher_builder::algorithm() const
{
    return _algo;
}

const std::string& cipher_builder::mode() const
{
    return _mode;
}

const std::string& cipher_builder::padding() const
{
    return _pad;
}

const std::string& cipher_builder::md() const
{
    return _md;
}

const cxy::security::key* cipher_builder::key() const
{
    return _key;
}

const std::vector<uint8_t/*std::byste*/>& cipher_builder::initial_vector() const
{
    return _iv;
}

std::shared_ptr<cipher> cipher_builder::encrypt()
{
//    return openssl::evp_cipher::get(_algo, _mode, _pad, _key, _iv, true);
    std::shared_ptr<cipher> ciph;
    ciph = openssl::evp_cipher::get(_algo, _mode, _pad, _key, _iv, true);
    if(ciph)
        return ciph;
    ciph = openssl::evp_pkey_cipher::get(_algo, _pad, _md, _key, true);
    return ciph;
}

std::shared_ptr<cipher> cipher_builder::decrypt()
{
//    return openssl::evp_cipher::get(_algo, _mode, _pad, _key, _iv, false);
    std::shared_ptr<cipher> ciph;
    ciph = openssl::evp_cipher::get(_algo, _mode, _pad, _key, _iv, false);
    if(ciph)
        return ciph;
    ciph = openssl::evp_pkey_cipher::get(_algo, _pad, _md, _key, false);
    return ciph;
}

std::shared_ptr<message_digest> cipher_builder::digest()
{
    return openssl::evp_md::get(_md);
}

std::shared_ptr<signature> cipher_builder::sign()
{
    return openssl::evp_sign::get(*this);
}

std::shared_ptr<verifier> cipher_builder::verify()
{
    return openssl::evp_verify::get(*this);
}


//
// PEM reader
//

std::shared_ptr<pem_reader> pem_reader::from_file(const std::string& path)
{
    return std::make_shared<openssl::ossl_FILE_pem_reader>(path);
}

std::shared_ptr<pem_reader> pem_reader::from_memory(const void* data, size_t sz)
{
    return std::make_shared<openssl::ossl_FILE_pem_reader>(data, sz);
}

std::shared_ptr<pem_reader> pem_reader::from_string(const std::string& str)
{
    return std::make_shared<openssl::ossl_string_pem_reader>(str);
}


}} // namespace cxy::security
