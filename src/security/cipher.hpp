/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/cipher.hpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
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

#ifndef _SECURITY_CIPHER_HPP_
#define _SECURITY_CIPHER_HPP_

#include <memory>

#include "key.hpp"

#define CXY_CIPHER_NO_PADDING      "NoPadding"
#define CXY_CIPHER_PKCS5_PADDING   "PKCS5Padding"
#define CXY_CIPHER_PKCS7_PADDING   "PKCS7Padding"

#define CXY_CIPHER_MODE_NONE    "NONE"
#define CXY_CIPHER_MODE_CBC     "CBC"
#define CXY_CIPHER_MODE_CFB     "CFB"
#define CXY_CIPHER_MODE_CFB1    "CFB1"
#define CXY_CIPHER_MODE_CFB8    "CFB8"
#define CXY_CIPHER_MODE_CFB128  "CFB128"
#define CXY_CIPHER_MODE_CTR     "CTR"
#define CXY_CIPHER_MODE_CTS     "CTS"
#define CXY_CIPHER_MODE_ECB     "ECB"
#define CXY_CIPHER_MODE_GCM     "GCM"
#define CXY_CIPHER_MODE_OFB     "OFB"


#define CXY_CIPHER_AES       "AES"
#define CXY_CIPHER_AES_128   "AES_128"
#define CXY_CIPHER_AES_192   "AES_192"
#define CXY_CIPHER_AES_256   "AES_256"



namespace cxy
{
namespace security
{

class cipher
{
public:
    virtual cipher& update_aad(const void* data, size_t sz) =0;

    virtual std::vector<uint8_t/*std::byte*/> update(const void* data, size_t sz) =0;

    virtual std::vector<uint8_t/*std::byte*/> finalize() =0;
    virtual std::vector<uint8_t/*std::byte*/> finalize(const void* data, size_t sz) =0;
};


class cipher_builder
{
public:
    cipher_builder() = default;

    cipher_builder& algorithm(const std::string& algo);
    cipher_builder& mode(const std::string& mode);
    cipher_builder& padding(const std::string& padding);
    cipher_builder& key(cxy::security::key& key);
    cipher_builder& initial_vector(const std::vector<uint8_t/*std::byte*/> iv);

    std::shared_ptr<cipher> encrypt();
    std::shared_ptr<cipher> decrypt();

private:
    std::string _algo, _mode, _pad;
    const cxy::security::key* _key;
    std::vector<uint8_t/*std::byste*/> _iv;
};

}} // namespace cxy::security
#endif // _SECURITY_CIPHER_HPP_
