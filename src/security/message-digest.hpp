/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/message-digest.hpp
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

#ifndef _SECURITY_MESSAGE_DIGEST_HPP_
#define _SECURITY_MESSAGE_DIGEST_HPP_

#include <memory>
#include <vector>

#include "security/exceptions.hpp"

namespace cxy
{
namespace security
{

/**
 * Message digest.
 */
class message_digest
{
public:

    /**
     * Look for a message digest with a specific algorithm.
     * \param algorithm Algorithm name
     * \return Message digest if available, nullptr otherwise.
     */
    static std::shared_ptr<message_digest> get(const std::string& algorithm);

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

}} // namespace cxy::security
#endif // _SECURITY_MESSAGE_DIGEST_HPP_
