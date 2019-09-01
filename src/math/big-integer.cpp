/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * math/big-integer.cpp
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

#include "big-integer.hpp"

namespace cxy
{
namespace math
{

big_integer::big_integer()
{
	mpz_init(__integ);
}

big_integer::big_integer(const big_integer& integer)
{
	mpz_init_set(__integ, integer.__integ);
}

big_integer::big_integer(big_integer&& integer)
{
	mpz_init(__integ);
	mpz_swap(__integ, integer.__integ);
}

big_integer::big_integer(unsigned long int number)
{
	mpz_init_set_ui(__integ, number);
}

big_integer::big_integer(signed long int number)
{
	mpz_init_set_si(__integ, number);
}

big_integer::big_integer(double number)
{
	mpz_init_set_d(__integ, number);
}

big_integer::big_integer(const std::string& str, int base)
{
	mpz_init_set_str(__integ, str.c_str(), base);
}

big_integer::big_integer(const char* str, int base)
{
	mpz_init_set_str(__integ, str, base);
}

big_integer::~big_integer()
{
	mpz_clear(__integ);
}

void big_integer::from_big_integer(const big_integer& number)
{
	mpz_set(__integ, number.__integ);
}

void big_integer::from_unsigned_long_long(unsigned long long number)
{
	mpz_import(__integ, 1, -1, sizeof number, 0, 0, &number);
}

void big_integer::from_unsigned_long_int(unsigned long int number)
{
	mpz_set_ui(__integ, number);
}

void big_integer::from_signed_long_long(signed long long number)
{
	unsigned long long ull = std::abs(number);
	from_unsigned_long_long(ull);
	if(number<0)
		mpz_neg(__integ, __integ);
}

void big_integer::from_signed_long_int(signed long int number)
{
	mpz_set_si(__integ, number);
}

void big_integer::from_double(double number)
{
	mpz_set_d(__integ, number);
}

bool big_integer::from_string(const std::string& str, int base)
{
	return mpz_set_str(__integ, str.c_str(), 0) == 0;
}

bool big_integer::from_string(const char* str, int base)
{
	return mpz_set_str(__integ, str, 0) == 0;
}

unsigned long long big_integer::to_unsigned_long_long()const
{
	unsigned long long result = 0;
    mpz_export(&result, 0, -1, sizeof result, 0, 0, __integ);
    return result;
}

unsigned long int big_integer::to_unsigned_long_int()const
{
	return mpz_get_ui(__integ);
}

signed long long big_integer::to_signed_long_long()const
{
	signed long long result = 0;
	mpz_export(&result, 0, -1, sizeof result, 0, 0, __integ);
	if(signum()<0)
		return -result;
	else
		return result;
}

signed long int big_integer::to_signed_long_int()const
{
	return mpz_get_si(__integ);
}

double big_integer::to_double()const
{
	return mpz_get_d(__integ);
}

std::string big_integer::to_string(int base)const
{
	int sz = mpz_sizeinbase(__integ, base);
	char *arr = new char[sz];
	mpz_get_str(arr, base, __integ);
	std::string str(arr);
	delete [] arr;
	return str;
}

big_integer big_integer::operator - () const
{
	big_integer res;
	mpz_neg(res.__integ, __integ);
	return res;
}

big_integer big_integer::operator + (const big_integer& integer)const
{
	big_integer res;
	mpz_add(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer& big_integer::operator += (const big_integer& integer)
{
	mpz_add(__integ, __integ, integer.__integ);
	return *this;
}

big_integer big_integer::operator + (unsigned long int integer)const
{
	big_integer res;
	mpz_add_ui(res.__integ, __integ, integer);
	return res;
}

big_integer& big_integer::operator += (unsigned long int integer)
{
	mpz_add_ui(__integ, __integ, integer);
	return *this;
}

big_integer big_integer::operator - (const big_integer& integer)const
{
	big_integer res;
	mpz_sub(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer& big_integer::operator -= (const big_integer& integer)
{
	mpz_sub(__integ, __integ, integer.__integ);
	return *this;
}

big_integer big_integer::operator - (unsigned long int integer)const
{
	big_integer res;
	mpz_sub_ui(res.__integ, __integ, integer);
	return res;
}

big_integer& big_integer::operator -= (unsigned long int integer)
{
	mpz_sub_ui(__integ, __integ, integer);
	return *this;
}

big_integer big_integer::operator * (const big_integer& integer)const
{
	big_integer res;
	mpz_mul(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer& big_integer::operator *= (const big_integer& integer)
{
	mpz_mul(__integ, __integ, integer.__integ);
	return *this;
}

big_integer big_integer::operator * (unsigned long int integer)const
{
	big_integer res;
	mpz_mul_ui(res.__integ, __integ, integer);
	return res;
}

big_integer& big_integer::operator *= (unsigned long int integer)
{
	mpz_mul_ui(__integ, __integ, integer);
	return *this;
}

big_integer big_integer::operator * (signed long int integer)const
{
	big_integer res;
	mpz_mul_si(res.__integ, __integ, integer);
	return res;
}

big_integer& big_integer::operator *= (signed long int integer)
{
	mpz_mul_si(__integ, __integ, integer);
	return *this;
}

big_integer big_integer::abs()const
{
	big_integer res;
	mpz_abs(res.__integ, __integ);
	return res;
}

// Division and modulus note:
// Should be kept in "ceiling" mode or replace to floor or truncate mode ?
// https://gmplib.org/manual/Integer-Division.html

big_integer big_integer::operator / (const big_integer& integer)const
{
	big_integer res;
	mpz_cdiv_q(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer& big_integer::operator /= (const big_integer& integer)
{
	mpz_cdiv_q(__integ, __integ, integer.__integ);
	return *this;
}

big_integer big_integer::operator / (unsigned long int integer)const
{
	big_integer res;
	mpz_cdiv_q_ui(res.__integ, __integ, integer);
	return res;
}

big_integer& big_integer::operator /= (unsigned long int integer)
{
	mpz_cdiv_q_ui(__integ, __integ, integer);
	return *this;
}

big_integer big_integer::operator % (const big_integer& integer)const
{
	big_integer res;
	mpz_cdiv_r(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer& big_integer::operator %= (const big_integer& integer)
{
	mpz_cdiv_r(__integ, __integ, integer.__integ);
	return *this;
}

big_integer big_integer::operator % (unsigned long int integer)const
{
	big_integer res;
	mpz_cdiv_r_ui(res.__integ, __integ, integer);
	return res;
}

big_integer& big_integer::operator %= (unsigned long int integer)
{
	mpz_cdiv_r_ui(__integ, __integ, integer);
	return *this;
}

std::pair<big_integer,big_integer> big_integer::div(const big_integer& integer)const
{
	std::pair<big_integer,big_integer> pair;
	mpz_cdiv_qr(pair.first.__integ, pair.second.__integ, __integ, integer.__integ);
	return pair;
}

std::pair<big_integer,big_integer> big_integer::div(unsigned long int integer)const
{
	std::pair<big_integer,big_integer> pair;
	mpz_cdiv_qr_ui(pair.first.__integ, pair.second.__integ, __integ, integer);
	return pair;
}


big_integer big_integer::mod(const big_integer& integer)const
{
	big_integer res;
	mpz_cdiv_r(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer big_integer::mod(unsigned long int integer)const
{
	big_integer res;
	mpz_cdiv_r_ui(res.__integ, __integ, integer);
	return res;
}

big_integer big_integer::mod_inverse(const big_integer& integer)const
{
	big_integer res;
	mpz_invert(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer big_integer::mod_pow(const big_integer& exponent, const big_integer& modulus)const
{
	big_integer res;
	mpz_powm(res.__integ, __integ, exponent.__integ, modulus.__integ);
	return res;
}

big_integer::PrimeProbability big_integer::is_probable_prime(int reps)const
{
	return (big_integer::PrimeProbability)mpz_probab_prime_p(__integ, reps);
}

big_integer big_integer::next_prime()const
{
	big_integer res;
	mpz_nextprime(res.__integ, __integ);
	return res;
}

big_integer big_integer::gcd(const big_integer& integer)const
{
	big_integer res;
	mpz_gcd(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer big_integer::gcd(unsigned long int integer)const
{
	big_integer res;
	mpz_gcd_ui(res.__integ, __integ, integer);
	return res;
}

big_integer big_integer::lcm(const big_integer& integer)const
{
	big_integer res;
	mpz_lcm(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer big_integer::lcm(unsigned long int integer)const
{
	big_integer res;
	mpz_lcm_ui(res.__integ, __integ, integer);
	return res;
}

int big_integer::compare(const big_integer& integer)const
{
	return mpz_cmp(__integ, integer.__integ);
}

int big_integer::compare(unsigned long int integer)const
{
	return mpz_cmp_ui(__integ, integer);
}

int big_integer::compare(signed long int integer)const
{
	return mpz_cmp_si(__integ, integer);
}

int big_integer::compare(double number)const
{
	return mpz_cmp_d(__integ, number);
}

int big_integer::compare_absolute(const big_integer& integer)const
{
	return mpz_cmpabs(__integ, integer.__integ);
}

int big_integer::compare_absolute(unsigned long int integer)const
{
	return mpz_cmpabs_ui(__integ, integer);
}

int big_integer::compare_absolute(double number)const
{
	return mpz_cmpabs_d(__integ, number);
}

int big_integer::signum()const
{
	return mpz_sgn(__integ);
}

bool big_integer::odd()const
{
	return mpz_odd_p(__integ);
}

bool big_integer::even()const
{
	return mpz_even_p(__integ);
}

big_integer big_integer::operator & (const big_integer& integer)const
{
	big_integer res;
	mpz_and(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer& big_integer::operator &= (const big_integer& integer)
{
	mpz_and(__integ, __integ, integer.__integ);
	return *this;
}

big_integer big_integer::operator | (const big_integer& integer)const
{
	big_integer res;
	mpz_ior(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer& big_integer::operator |= (const big_integer& integer)
{
	mpz_ior(__integ, __integ, integer.__integ);
	return *this;
}

big_integer big_integer::operator ^ (const big_integer& integer)const
{
	big_integer res;
	mpz_xor(res.__integ, __integ, integer.__integ);
	return res;
}

big_integer& big_integer::operator ^= (const big_integer& integer)
{
	mpz_xor(__integ, __integ, integer.__integ);
	return *this;
}

big_integer big_integer::operator ~ ()const
{
	big_integer res;
	mpz_com(res.__integ, __integ);
	return res;
}

bool big_integer::get(size_t pos)const
{
	return mpz_tstbit(__integ, pos) != 0;
}

big_integer& big_integer::set(size_t pos, bool value)
{
	if(value)
		mpz_setbit(__integ, pos);
	else
		mpz_clrbit(__integ, pos);
	return *this;
}

big_integer& big_integer::reset(size_t pos)
{
	mpz_clrbit(__integ, pos);
	return *this;
}

big_integer& big_integer::flip(size_t pos)
{
	mpz_combit(__integ, pos);
	return *this;
}

unsigned long int big_integer::count()const
{
	return mpz_popcount(__integ);
}

void big_integer::swap(big_integer& integer)
{
	mpz_swap(__integ, integer.__integ);
}

}} // namespace cxy::math
