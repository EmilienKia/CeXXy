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


#include "crypto.hpp"


#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <map>
#include <functional>

#include <cstdio>


namespace cxy
{
namespace security
{
namespace openssl
{

cxy::math::big_integer bn2bi(const BIGNUM *bn);

BIGNUM* bi2bn(const cxy::math::big_integer& bi, BIGNUM* bn = nullptr);

//
// EVP Message Digest
//

class evp_md : public message_digest
{
    // TODO Add a better way to handle algorithm name.
protected:
    EVP_MD_CTX* _mdctx;
    std::string _algo;

public:

    static std::map<std::string, std::function<const EVP_MD*()>> _evp;
    static const EVP_MD * get_EVP_MD(const std::string& algorithm);

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


class evp_sign : public signature
{
    // TODO Add a better way to handle algorithm name.
protected:
    EVP_MD_CTX* _mdctx = nullptr;
    EVP_PKEY_CTX* _pkctx = nullptr;
    std::string _algo;
    const private_key* _pkey;

public:

    static std::shared_ptr<evp_sign> get(const cipher_builder& bldr);

    evp_sign() = delete;
    evp_sign(evp_sign&& other) = default;
    evp_sign(const evp_sign& other) = delete;

    evp_sign(const EVP_MD *md, const std::string& algo, const private_key* key, EVP_PKEY* pkey);
    virtual ~evp_sign();

    virtual signature& update(const void* data, size_t size) override;
    virtual std::vector<uint8_t /*std::byte*/>  sign() override;
};

class evp_verify : public verifier
{
protected:
    EVP_MD_CTX* _mdctx = nullptr;
    EVP_PKEY_CTX* _pkctx = nullptr;
    std::string _algo;
    const public_key* _pkey;


public:
    static std::shared_ptr<evp_verify> get(const cipher_builder& bldr);

    evp_verify() = delete;
    evp_verify(evp_verify&& other) = default;
    evp_verify(const evp_verify& other) = delete;

    evp_verify(const EVP_MD *md, const std::string& algo, const public_key* key, EVP_PKEY* pkey);
    virtual ~evp_verify();

    virtual verifier& update(const void* data, size_t size) override;
    bool verify(const void* data, size_t size) override;
};

//
// EVP based symmetric cipher support
//

class evp_cipher : public cipher
{
private:
    EVP_CIPHER_CTX *_ctx = nullptr;

public:
    static const EVP_CIPHER* find_EVP_CIPHER(const cipher_builder& bldr);
    static std::shared_ptr<cipher> get(const std::string& algorithm, const std::string& mode, const std::string& padding, const cxy::security::key* key, const std::vector<uint8_t/*std::byte*/>& iv, bool encrypt);

    evp_cipher(const EVP_CIPHER *type, bool padding, const unsigned char *key, const unsigned char *iv, bool enc);
    virtual ~evp_cipher();

    const EVP_CIPHER* get_EVP_CIPHER() const { return _ctx!=nullptr ? EVP_CIPHER_CTX_cipher(_ctx) : nullptr; }

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

    static EVP_PKEY* get(const std::string& algorithm, const cxy::security::key* key);

    static std::shared_ptr<cipher> get(const std::string& algorithm, const std::string& padding, const std::string& md, const cxy::security::key* key, bool encrypt);

    evp_pkey_cipher(EVP_PKEY *pkey, EVP_PKEY_PADDING_MODE padding, const std::string& md, bool enc);
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
    virtual size_t modulus_size() const override;
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


//
// Various internal openssl converting functions
//
std::shared_ptr<ossl_rsa_private_key> make_rsa_private_key(RSA* rsa);
std::shared_ptr<public_key> make_public_key(EVP_PKEY* pkey);




//
// X500 Principal
//

class ossl_x500_principal : public x500_principal
{
private:
    std::shared_ptr<X509_NAME> _name;

public:
    ossl_x500_principal() = default;
    ossl_x500_principal(ossl_x500_principal&&) = default;
    ossl_x500_principal(const ossl_x500_principal&) = default;
    ossl_x500_principal& operator=(ossl_x500_principal&&) = default;
    ossl_x500_principal& operator=(const ossl_x500_principal&) = default;

    ossl_x500_principal(X509_NAME* name);

    operator bool()const;

    virtual std::string name() const override;
};


//
// X509 Certificate
//


class ossl_x509_certificate : public x509_certificate
{
private:
    std::shared_ptr<X509> _cert;

    mutable ossl_x500_principal _subject, _issuer;
    mutable std::shared_ptr<security::public_key> _pubkey;

public:
    ossl_x509_certificate(X509* cert);
    virtual ~ossl_x509_certificate() = default;

    virtual long version() const override;

    virtual std::shared_ptr<security::public_key> public_key() const override;

    virtual const x500_principal& subject() const override;
    virtual const x500_principal& issuer() const override;

    virtual cxy::math::big_integer serial_number() const override;
};


//
// PEM Readers
//



class ossl_FILE_pem_reader : public pem_reader
{
protected:
    std::shared_ptr<std::FILE> _fp;

public:
    ossl_FILE_pem_reader() = default;
    ossl_FILE_pem_reader(const ossl_FILE_pem_reader&) = delete;
    ossl_FILE_pem_reader(ossl_FILE_pem_reader&&) = default;
    virtual ~ossl_FILE_pem_reader() = default;

    ossl_FILE_pem_reader(FILE* f);
    ossl_FILE_pem_reader(const std::string& path);
    ossl_FILE_pem_reader(const void *buf, size_t size);

    virtual std::shared_ptr<security::public_key> public_key() override;
    virtual std::shared_ptr<security::rsa_public_key> rsa_public_key() override;
    virtual std::shared_ptr<security::private_key> private_key() override;
    virtual std::shared_ptr<security::private_key> private_key(const std::string& passwd) override;
    virtual std::shared_ptr<security::rsa_private_key> rsa_private_key() override;
    virtual std::shared_ptr<security::rsa_private_key> rsa_private_key(const std::string& passwd) override;

    virtual std::shared_ptr<security::x509_certificate> x509_certificate() override;

};

class ossl_string_pem_reader : public ossl_FILE_pem_reader
{
    std::unique_ptr<std::string> _str;

public:
    ossl_string_pem_reader() = delete;
    ossl_string_pem_reader(const ossl_string_pem_reader&) = delete;
    ossl_string_pem_reader(ossl_string_pem_reader&&) = default;
    virtual ~ossl_string_pem_reader() = default;

    ossl_string_pem_reader(const std::string& str);

};


//
// PEM Writers
//

class ossl_FILE_pem_writer : public virtual pem_writer
{
protected:
    std::shared_ptr<std::FILE> _fp;

public:
    ossl_FILE_pem_writer() = default;
    ossl_FILE_pem_writer(const ossl_FILE_pem_writer&) = delete;
    ossl_FILE_pem_writer(ossl_FILE_pem_writer&&) = delete;
    virtual ~ossl_FILE_pem_writer() = default;

    ossl_FILE_pem_writer(FILE* f);
    ossl_FILE_pem_writer(const std::string& path, bool append);

    virtual void public_key(const security::public_key& key) override;
    virtual void rsa_public_key(const security::rsa_public_key& key) override;
    virtual void private_key(const security::private_key& key) override;
    virtual void private_key(const security::private_key& key, const security::cipher_builder& cipher, const std::string& passwd) override;
    virtual void rsa_private_key(const security::rsa_private_key& key) override;
    virtual void rsa_private_key(const security::rsa_private_key& key, const security::cipher_builder& cipher, const std::string& passwd) override;

};

class ossl_string_pem_writer : public ossl_FILE_pem_writer, public pem_string_writer
{
protected:
    mutable char* _str = nullptr;
    mutable size_t _sz = 0;

public:
    ossl_string_pem_writer();
    ossl_string_pem_writer(const ossl_string_pem_writer&) = delete;
    ossl_string_pem_writer(ossl_string_pem_writer&&) = delete;
    virtual ~ossl_string_pem_writer();

    virtual std::string str()const override;
};

}}} // namespace cxy::security::openssl
#endif // _SECURITY_OPENSSL_HPP_
