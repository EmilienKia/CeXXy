/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/openssl.hpp
 * Copyright (C) 2020 Emilien Kia <emilien.kia+dev@gmail.com>
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

#ifndef _SECURITY_OPENSSL_HPP_
#define _SECURITY_OPENSSL_HPP_

#include "../math/big-integer.hpp"

#include "key.hpp"
#include "cipher.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>


namespace cxy
{
namespace security
{
namespace openssl
{

cxy::math::big_integer bn2bi(const BIGNUM *bn);

BIGNUM* bi2bn(const cxy::math::big_integer& bi, BIGNUM* bn = nullptr);

//
// EVP based symmetric cipher support
//

class evp_cipher : public cipher
{
private:
    EVP_CIPHER_CTX *_ctx = nullptr;

public:
    static std::shared_ptr<cipher> get(const std::string& algorithm, const std::string& mode, const std::string& padding, const cxy::security::key* key, const std::vector<uint8_t/*std::byte*/>& iv, bool encrypt);

    evp_cipher(const EVP_CIPHER *type, bool padding, const unsigned char *key, const unsigned char *iv, bool enc);
    virtual ~evp_cipher();

    virtual cipher& update_aad(const void* data, size_t sz) override;
    virtual std::vector<uint8_t/*std::byte*/> update(const void* data, size_t sz) override;

    virtual std::vector<uint8_t/*std::byte*/> finalize() override;
    virtual std::vector<uint8_t/*std::byte*/> finalize(const void* data, size_t sz) override;
};

//
// EVP PKEY based asymmetric cipher support
//

class evp_pkey_cipher : public cipher
{
public:
    enum EVP_PKEY_PADDING_MODE {
        RSA_PAD_NONE,   // RSA_NO_PADDING
        RSA_PAD_PKCS1,  // RSA_PKCS1_PADDING
        RSA_PAD_OAEP // RSA_PKCS1_OAEP_PADDING
    };
private:
    EVP_PKEY_CTX * _ctx = nullptr;
    bool _encode;

public:
    static std::shared_ptr<cipher> get(const std::string& algorithm, const std::string& padding, const cxy::security::key* key, bool encrypt);

    evp_pkey_cipher(EVP_PKEY *pkey, EVP_PKEY_PADDING_MODE padding, bool enc);
    virtual ~evp_pkey_cipher();

    virtual cipher& update_aad(const void* data, size_t sz) override;
    virtual std::vector<uint8_t/*std::byte*/> update(const void* data, size_t sz) override;

    virtual std::vector<uint8_t/*std::byte*/> finalize() override;
    virtual std::vector<uint8_t/*std::byte*/> finalize(const void* data, size_t sz) override;
};



//
// RSA
//

typedef std::shared_ptr<RSA> RSA_sptr;

class ossl_rsa_key : public virtual rsa_key
{
protected:
    RSA_sptr _rsa;

    ossl_rsa_key() = default;

public:
    ossl_rsa_key(RSA* rsa);

    RSA* get() {return _rsa.get();}
    const RSA* get() const {return _rsa.get();}

    virtual cxy::math::big_integer modulus() const override;
};


class ossl_rsa_public_key : public virtual ossl_rsa_key, public virtual rsa_public_key
{
public:
    ossl_rsa_public_key(RSA* rsa);

    virtual cxy::math::big_integer public_exponent() const override;
};

class ossl_rsa_private_key : public virtual ossl_rsa_key, public virtual rsa_private_key
{
protected:
    ossl_rsa_private_key() = default;
public:
    ossl_rsa_private_key(RSA* rsa);

    virtual cxy::math::big_integer private_exponent() const override;
};

class ossl_rsa_private_crt_key : public virtual ossl_rsa_private_key, public virtual rsa_private_crt_key
{
protected:
    ossl_rsa_private_crt_key() = default;
public:
    ossl_rsa_private_crt_key(RSA* rsa);

    virtual cxy::math::big_integer private_exponent() const override;
    virtual cxy::math::big_integer crt_coefficient() const override;
    virtual cxy::math::big_integer prime_exponent_p() const override;
    virtual cxy::math::big_integer prime_exponent_q() const override;
    virtual cxy::math::big_integer prime_p() const override;
    virtual cxy::math::big_integer prime_q() const override;
    virtual cxy::math::big_integer public_exponent() const override;
};

class ossl_rsa_multiprime_private_crt_key : public virtual ossl_rsa_private_crt_key, public virtual rsa_multiprime_private_crt_key
{
public:
    ossl_rsa_multiprime_private_crt_key(RSA* rsa);

    virtual cxy::math::big_integer private_exponent() const override;
    virtual cxy::math::big_integer crt_coefficient() const override;
    virtual cxy::math::big_integer prime_exponent_p() const override;
    virtual cxy::math::big_integer prime_exponent_q() const override;
    virtual cxy::math::big_integer prime_p() const override;
    virtual cxy::math::big_integer prime_q() const override;
    virtual cxy::math::big_integer public_exponent() const override;
    virtual std::vector<cxy::math::big_integer> other_prime_info() const override;
};

std::shared_ptr<ossl_rsa_private_key> make_rsa_private_key(RSA* rsa);



class ossl_rsa_key_pair : public rsa_key_pair
{
    RSA_sptr _rsa;

    mutable std::shared_ptr<ossl_rsa_public_key> _pub;
    mutable std::shared_ptr<ossl_rsa_private_key> _priv;

public:
    ossl_rsa_key_pair(RSA* rsa);

    virtual std::shared_ptr<cxy::security::rsa_public_key> rsa_public_key() const override;
    virtual std::shared_ptr<cxy::security::rsa_private_key> rsa_private_key() const override;
};


class ossl_rsa_key_pair_generator : public rsa_key_pair_generator
{
    size_t _key_size = 2048;
    cxy::math::big_integer _pub = rsa_key_pair_generator::F0;

public:
    ossl_rsa_key_pair_generator() = default;

    virtual rsa_key_pair_generator& key_size(size_t key_size) override;
    virtual rsa_key_pair_generator& public_exponent(const cxy::math::big_integer& pub) override;
    virtual size_t key_size() const override;
    virtual cxy::math::big_integer public_exponent() const;
    virtual std::shared_ptr<key_pair> generate() override;
};


}}} // namespace cxy::security::openssl
#endif // _SECURITY_OPENSSL_HPP_
