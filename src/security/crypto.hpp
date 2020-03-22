/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/crypto.hpp
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

#ifndef _SECURITY_CRYPTO_HPP_
#define _SECURITY_CRYPTO_HPP_

#include <memory>
#include <vector>
#include <initializer_list>

#include "../math/big-integer.hpp"
#include "exceptions.hpp"


//
// Cipher Padding
//

#define CXY_CIPHER_NO_PADDING      "NoPadding"

// Symmetric key (AES) cipher padding
#define CXY_CIPHER_PKCS5_PADDING   "PKCS5Padding"
#define CXY_CIPHER_PKCS7_PADDING   "PKCS7Padding"

// RSA cipher padding
#define CXY_CIPHER_PKCS1_PADDING        "PKCS1Padding"
#define CXY_CIPHER_PKCS1_OAEP_PADDING    "OAEPPadding"


//
// Cipher mode
//
#define CXY_CIPHER_MODE_NONE    "NONE"
#define CXY_CIPHER_MODE_CBC     "CBC"
#define CXY_CIPHER_MODE_CFB     "CFB"
#define CXY_CIPHER_MODE_CFB1    "CFB1"
#define CXY_CIPHER_MODE_CFB8    "CFB8"
#define CXY_CIPHER_MODE_CFB64   "CFB64"
#define CXY_CIPHER_MODE_CFB128  "CFB128"
#define CXY_CIPHER_MODE_CTR     "CTR"
#define CXY_CIPHER_MODE_ECB     "ECB"
#define CXY_CIPHER_MODE_OFB     "OFB"
#define CXY_CIPHER_MODE_CTS     "CTS"
#define CXY_CIPHER_MODE_GCM     "GCM"

//
// Cipher algorithm
//
#define CXY_CIPHER_AES       "AES"
#define CXY_CIPHER_ARIA      "ARIA"
#define CXY_CIPHER_BLOWFISH  "Blowfish"
#define CXY_CIPHER_CAMELLIA  "Camellia"
#define CXY_CIPHER_CAST5     "Cast5"
#define CXY_CIPHER_IDEA      "IDEA"
#define CXY_CIPHER_SM4       "SM4"
#define CXY_CIPHER_CHACHA20  "ChaCha20"
#define CXY_CIPHER_CHACHA20_POLY1305       "ChaCha20-Poly1305"

#define CXY_CIPHER_RSA       "RSA"

//
// Key types
//
#define CXY_KEY_RSA       "RSA"


namespace cxy
{
namespace security
{

/**
 * Base interface for all cryptographic keys.
 */
class key
{
public:
//    key() = default;
//    key(key&&) = default;
//    key(const key&) = default;
//    virtual ~key() = delete;
    virtual ~key() = default;

    /**
     * Return the algorithm of
     */
//    virtual std::string algorithm()const = 0;
};

/**
 * Base interface for all public keys.
 */
class public_key : public virtual key
{
public:
//    virtual ~public_key() = delete;
};

/**
 * Base interface for all private keys.
 */
class private_key : public virtual key
{
public:
//    virtual ~private_key() = delete;
};

/**
 * Base interface for all secret keys.
 */
class secret_key : public virtual key
{
public:
//    secret_key() = default;
//    virtual ~secret_key() = delete;
    /** Size of the key in bytes. */
    virtual size_t size() const =0;
    /** Retrieve the raw value content of the key. */
    virtual std::vector<uint8_t/*std::byte*/> value()const=0;
};

/**
 * Base interface for key pair.
 */
class key_pair
{
public:
    virtual std::shared_ptr<cxy::security::public_key> public_key() const =0;
    virtual std::shared_ptr<cxy::security::private_key> private_key() const =0;
};

/**
 *
 */
class key_pair_generator
{
public:
    virtual std::string algorithm() const =0;
    virtual std::shared_ptr<key_pair> generate() =0;
};




class raw_secret_key : public secret_key
{
protected:
    std::vector<uint8_t/*std::byte*/> _value;

public:
    raw_secret_key() = default;
    raw_secret_key(std::initializer_list<uint8_t/*std::byte*/> init):
        _value(init) {}

    template<typename ... Args>
    raw_secret_key(Args&& ... args):_value(args...) {}

    virtual ~raw_secret_key() = default;

    virtual size_t size() const {return _value.size(); }

    virtual std::vector<uint8_t/*std::byte*/> value()const { return _value;}
    std::vector<uint8_t/*std::byte*/>& value() { return _value;}

};





class rsa_key : public virtual key
{
public:
    virtual cxy::math::big_integer modulus() const =0;
};


class rsa_public_key : public virtual public_key, public virtual rsa_key
{
public:
    virtual cxy::math::big_integer public_exponent() const =0;
};

class rsa_private_key : public virtual private_key, public virtual rsa_key
{
public:
    virtual cxy::math::big_integer private_exponent() const =0;
};

class rsa_private_crt_key : public virtual rsa_private_key
{
public:
    virtual cxy::math::big_integer crt_coefficient() const =0;
    virtual cxy::math::big_integer prime_exponent_p() const =0;
    virtual cxy::math::big_integer prime_exponent_q() const =0;
    virtual cxy::math::big_integer prime_p() const =0;
    virtual cxy::math::big_integer prime_q() const =0;
    virtual cxy::math::big_integer public_exponent() const =0;
};

class rsa_multiprime_private_crt_key : public virtual rsa_private_crt_key
{
public:
    virtual std::vector<cxy::math::big_integer> other_prime_info() const =0;
};

class rsa_key_pair_generator;

class rsa_key_pair : public virtual key_pair
{
public:
    virtual std::shared_ptr<cxy::security::rsa_public_key> rsa_public_key() const =0;
    virtual std::shared_ptr<cxy::security::rsa_private_key> rsa_private_key() const =0;

    virtual std::shared_ptr<cxy::security::public_key> public_key() const override {
        return std::dynamic_pointer_cast<cxy::security::public_key>(rsa_public_key());
    }

    virtual std::shared_ptr<cxy::security::private_key> private_key() const override {
        return std::dynamic_pointer_cast<cxy::security::private_key>(rsa_private_key());
    }

    static std::shared_ptr<rsa_key_pair_generator> generator();
};

class rsa_key_pair_generator : public virtual key_pair_generator
{
public:
    static const cxy::math::big_integer F0;
    static const cxy::math::big_integer F4;

    virtual std::string algorithm() const override;

    virtual rsa_key_pair_generator& key_size(size_t key_size) =0;
    virtual rsa_key_pair_generator& public_exponent(const cxy::math::big_integer& pub) =0;

    virtual size_t key_size() const =0;
    virtual cxy::math::big_integer public_exponent() const =0;
};





/**
 * Message digest.
 */
class message_digest
{
public:

    /**
     * Return the algorithm name of the current message digest.
     * \return Algorithm name.
     */
    virtual std::string algorithm() const =0;

    /**
     * Return the length of the current digest, if fixed.
     * \return Digest size in bytes, 0 if variable.
     */
    virtual uint16_t digest_length() const =0;

    /**
     * Update the current digest computation with specified data.
     * \param data Pointer to the data to add.
     * \param size Size of data to add, in bytes.
     */
    virtual message_digest& update(const void* data, size_t size) =0;

    // TODO add template inline update methods.

    /**
     * Finalize the computation of the digest and returns it.
     * \return The computed digest.
     */
    virtual std::vector<uint8_t /*std::byte*/>  digest() =0;

    /**
     * Reset the digest computation for further use.
     */
    virtual message_digest& reset() =0;
};



class signature
{
public:
    virtual signature& update(const void* data, size_t size) =0;

    virtual std::vector<uint8_t /*std::byte*/>  sign() =0;
};


class verifier
{
public:
    virtual verifier& update(const void* data, size_t size) =0;

    virtual bool verify(const void* data, size_t size) =0;
};


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
    cipher_builder& md(const std::string& md);
    cipher_builder& key(cxy::security::key& key);
    cipher_builder& initial_vector(const std::vector<uint8_t/*std::byte*/> iv);

    const std::string& algorithm() const;
    const std::string& mode() const;
    const std::string& padding() const;
    const std::string& md() const;
    const cxy::security::key* key() const;
    const std::vector<uint8_t/*std::byste*/>& initial_vector() const;

    std::shared_ptr<cipher> encrypt();
    std::shared_ptr<cipher> decrypt();
    std::shared_ptr<message_digest> digest();
    std::shared_ptr<signature> sign();
    std::shared_ptr<verifier> verify();

private:
    std::string _algo, _mode, _pad, _md;
    const cxy::security::key* _key;
    std::vector<uint8_t/*std::byste*/> _iv;
};

}} // namespace cxy::security
#endif // _SECURITY_CIPHER_HPP_
