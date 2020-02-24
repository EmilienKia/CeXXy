/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/message-digest.cpp
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

#include "message-digest.hpp"

#include <openssl/evp.h>

#include "exceptions.hpp"

#include <exception>
#include <functional>
#include <map>

namespace cxy
{
namespace security
{

namespace openssl
{


class evp_md : public message_digest
{
    // TODO Add a better way to handle algorithm name.
protected:
    EVP_MD_CTX* _mdctx;
    std::string _algo;

    static std::map<std::string, std::function<const EVP_MD*()>> _evp;

public:
    static std::shared_ptr<evp_md> get(const std::string& algorithm);

    evp_md() = delete;
    evp_md(evp_md&& other) = default;

    evp_md(const EVP_MD *type, const std::string& algo);
    evp_md(const evp_md& other);
    virtual ~evp_md();

    virtual std::string algorithm() const override;
    virtual uint16_t digest_length() const override;

    virtual message_digest& update(const void* data, size_t size) override;
    virtual std::vector<uint8_t /*std::byte*/>  digest() override;
    virtual message_digest& reset() override;
};

std::map<std::string, std::function<const EVP_MD*()>> evp_md::_evp {
    {"NULL", EVP_md_null}
# ifndef OPENSSL_NO_MD2
    ,{"MD2", EVP_md2}
# endif
# ifndef OPENSSL_NO_MD4
    ,{"MD4", EVP_md4}
# endif
# ifndef OPENSSL_NO_MD5
    ,{"MD5", EVP_md5}
    ,{"MD5-SHA1", EVP_md5_sha1}
# endif
# ifndef OPENSSL_NO_BLAKE2
    ,{"BLAKE2S", EVP_blake2s256}
    ,{"BLAKE2B", EVP_blake2b512}
    ,{"BLAKE2-256", EVP_blake2s256}
    ,{"BLAKE2-512", EVP_blake2b512}
# endif
    ,{"SHA1", EVP_sha1}
    ,{"SHA2-224", EVP_sha224}, {"SHA-224", EVP_sha224}
    ,{"SHA2-256", EVP_sha256}, {"SHA-256", EVP_sha256}
    ,{"SHA2-384", EVP_sha384}, {"SHA-384", EVP_sha384}
    ,{"SHA2-512", EVP_sha512}, {"SHA-512", EVP_sha512}
    ,{"SHA2-512-224", EVP_sha512_224}, {"SHA-512-224", EVP_sha512_224}
    ,{"SHA2-512-256", EVP_sha512_256}, {"SHA-512-256", EVP_sha512_256}
    ,{"SHA3-224", EVP_sha3_224}
    ,{"SHA3-256", EVP_sha3_256}
    ,{"SHA3-384", EVP_sha3_384}
    ,{"SHA3-512", EVP_sha3_512}
    ,{"SHAKE-128", EVP_shake128}
    ,{"SHAKE-256", EVP_shake256}
# ifndef OPENSSL_NO_MDC2
    ,{"SMDC2", EVP_mdc2}
# endif
# ifndef OPENSSL_NO_RMD160
    ,{"RIPEMD-160", EVP_ripemd160}
# endif
# ifndef OPENSSL_NO_WHIRLPOOL
    ,{"WHIRLPOOL", EVP_whirlpool}
# endif
# ifndef OPENSSL_NO_SM3
    ,{"SM3", EVP_sm3}
#endif
};


std::shared_ptr<evp_md> evp_md::get(const std::string& algorithm)
{
    auto it = _evp.find(algorithm);
    if (it!=_evp.end()) {
        return std::make_shared<evp_md>(it->second(), it->first);
    } else {
        throw no_such_algorithm_exception(algorithm + " is not supported");
    }
}

evp_md::evp_md(const EVP_MD *type, const std::string& algo):
_algo(algo)
{
    _mdctx = EVP_MD_CTX_create();
    if(EVP_DigestInit_ex(_mdctx, type, nullptr)==0)
    {
        throw digest_exception("Cannot initialize digest");
    }
}

evp_md::evp_md(const evp_md& other)
{
    _mdctx = EVP_MD_CTX_create();
    if(EVP_MD_CTX_copy_ex(_mdctx, other._mdctx)==0)
    {
        throw digest_exception("Cannot copy digest");
    }
}

evp_md::~evp_md()
{
    if(_mdctx!=nullptr) {
        EVP_MD_CTX_free(_mdctx);
        _mdctx = nullptr;
    }
}

std::string evp_md::algorithm() const
{
    return _algo;
}

uint16_t evp_md::digest_length() const
{
    return EVP_MD_CTX_size(_mdctx);
}

message_digest& evp_md::update(const void* data, size_t size)
{
    if(EVP_DigestUpdate(_mdctx, data, size)==0)
    {
        throw digest_exception("Cannot update digest");
    }
    return *this;
}

std::vector<uint8_t /*std::byte*/> evp_md::digest()
{
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    if(EVP_DigestFinal_ex(_mdctx, md_value, &md_len)==0)
    {
        throw digest_exception("Cannot update digest");
    }
    return std::vector<uint8_t /*std::byte*/>(md_value, md_value+md_len);
}

message_digest& evp_md::reset()
{
    EVP_MD_CTX_reset(_mdctx);
    return *this;
}

} // namespace cxy::security::openssl


std::shared_ptr<message_digest> message_digest::get(const std::string& algorithm)
{
    return openssl::evp_md::get(algorithm);
}

}} // namespace cxy::security
