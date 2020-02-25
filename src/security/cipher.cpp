/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/cipher.cpp
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

#include "cipher.hpp"

#include "openssl.hpp"

#include <algorithm>

namespace cxy
{
namespace security
{

enum CIPHER_CHAIN_MODE
{
    CCMODE_NONE,
    CCMODE_CBC,
    CCMODE_CFB,
    CCMODE_CFB1,
    CCMODE_CFB8,
    CCMODE_CTR,
    CCMODE_CTS,
    CCMODE_ECB,
    CCMODE_GCM,
    CCMODE_OFB,
};



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


}} // namespace cxy::security
