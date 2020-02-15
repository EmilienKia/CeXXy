/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/key.hpp
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

#ifndef _SECURITY_KEY_HPP_
#define _SECURITY_KEY_HPP_

#include <memory>
#include <vector>
#include <initializer_list>

#include "../math/big-integer.hpp"

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

class rsa_private_crt_key : public rsa_private_key
{
public:
    virtual cxy::math::big_integer crt_coefficient() const =0;
    virtual cxy::math::big_integer prime_exponent_p() const =0;
    virtual cxy::math::big_integer prime_exponent_q() const =0;
    virtual cxy::math::big_integer prime_p() const =0;
    virtual cxy::math::big_integer prime_q() const =0;
    virtual cxy::math::big_integer public_exponent() const =0;
};

class rsa_multiprime_private_crt_key : public rsa_private_crt_key
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

}} // namespace cxy::security
#endif // _SECURITY_KEY_HPP_
