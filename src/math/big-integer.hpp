/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * math/big-integer.hpp
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

#ifndef _MATH_BIG_INTEGER_HPP_
#define _MATH_BIG_INTEGER_HPP_

#include <gmp.h>
#include <array>
#include <string>
#include <utility>
#include <vector>

namespace cxy
{
namespace math
{

/**
 *
 */
class big_integer
{
public:
	enum WordOrder {
		WORD_LEAST_SIGNIFICANT_FIRST = -1,
		WORD_MOST_SIGNIFICANT_FIRST = 1
	};
	enum Endianess {
		LEAST_SIGNIFICANT_FIRST = -1,
		MOST_SIGNIFICANT_FIRST = 1,
		NATIVE = 0
	};

	big_integer();
	big_integer(const big_integer& integer);
	big_integer(big_integer&& integer);
	big_integer(unsigned long int number);
	big_integer(signed long int number);
	big_integer(double number);
	big_integer(const std::string& str, int base = 0);
	big_integer(const char* str, int base = 0);

	template<typename T> big_integer(const T* ptr, size_t count, WordOrder order = WORD_MOST_SIGNIFICANT_FIRST, Endianess endian = NATIVE, size_t nails = 0):big_integer()
	{
		assign(ptr, count, order, endian, nails);
	}

	template<typename T> big_integer(const std::vector<T>& vec, WordOrder order = WORD_MOST_SIGNIFICANT_FIRST, Endianess endian = NATIVE, size_t nails = 0):big_integer()
	{
		assign(vec, order, endian, nails);
	}

	template<typename T, std::size_t N > big_integer(const std::array<T,N>& arr, WordOrder order = WORD_MOST_SIGNIFICANT_FIRST, Endianess endian = NATIVE, size_t nails = 0):big_integer()
	{
		assign(arr, order, endian, nails);
	}

	virtual ~big_integer();

	void from_big_integer(const big_integer& number);

	void from_unsigned_long_long(unsigned long long number);
	void from_unsigned_long_int(unsigned long int number);
	void from_unsigned_int(unsigned long int number){from_unsigned_long_int((unsigned long int)number);}
	void from_unsigned_short(unsigned short number){from_unsigned_long_int((unsigned long int)number);}

	void from_signed_long_long(signed long long number);
	void from_signed_long_int(signed long int number);
	void from_signed_int(signed long int number){from_signed_long_int((signed long int)number);}
	void from_signed_short(signed short number){from_signed_long_int((signed long int)number);}

	void from_double(double number);
	void from_float(float number){from_double((double)number);}

	bool from_string(const std::string& str, int base = 0);
	bool from_string(const char* str, int base = 0);

	unsigned long long to_unsigned_long_long()const;
	unsigned long int to_unsigned_long_int()const;
	unsigned int to_unsigned_int()const{return (unsigned int) to_unsigned_long_int();}
	unsigned short to_unsigned_short()const{return (unsigned short) to_unsigned_int();}

	signed long long to_signed_long_long()const;
	signed long int to_signed_long_int()const;
	signed int to_signed_int()const{return (signed int) to_signed_long_int();}
	signed short to_signed_short()const{return (signed short) to_signed_int();}

	double to_double()const;
	float to_float()const{return (float)to_double();}

	std::string to_string(int base = 10)const;

	big_integer& operator= (const big_integer& number){from_big_integer(number); return *this;}
	big_integer& operator= (unsigned long long number){from_unsigned_long_long(number); return *this;}
	big_integer& operator= (unsigned long int number){from_unsigned_long_int(number); return *this;}
	big_integer& operator= (unsigned int number){from_unsigned_int(number); return *this;}
	big_integer& operator= (unsigned short number){from_unsigned_short(number); return *this;}
	big_integer& operator= (signed long long number){from_signed_long_long(number); return *this;}
	big_integer& operator= (signed long int number){from_signed_long_int(number); return *this;}
	big_integer& operator= (signed int number){from_signed_int(number); return *this;}
	big_integer& operator= (signed short number){from_signed_short(number); return *this;}
	big_integer& operator= (double number){from_double(number); return *this;}
	big_integer& operator= (float number){from_float(number); return *this;}
	big_integer& operator= (const std::string& str){from_string(str); return *this;}
	big_integer& operator= (const char* str){from_string(str); return *this;}

	operator unsigned long long ()const{return to_unsigned_long_long();}
	operator unsigned long int ()const{return to_unsigned_long_int();}
	operator unsigned int ()const{return to_unsigned_int();}
	operator unsigned short ()const{return to_unsigned_short();}

	operator signed long long ()const{return to_signed_long_long();}
	operator signed long int ()const{return to_signed_long_int();}
	operator signed int ()const{return to_signed_int();}
	operator signed short ()const{return to_signed_short();}

	operator double ()const{return to_double();}
	operator float ()const{return to_float();}

	big_integer operator - ()const;

	big_integer operator + (const big_integer& integer)const;
	big_integer& operator += (const big_integer& integer);
	big_integer operator + (unsigned long int integer)const;
	big_integer& operator += (unsigned long int integer);

	big_integer operator - (const big_integer& integer)const;
	big_integer& operator -= (const big_integer& integer);
	big_integer operator - (unsigned long int integer)const;
	big_integer& operator -= (unsigned long int integer);

	big_integer operator * (const big_integer& integer)const;
	big_integer& operator *= (const big_integer& integer);
	big_integer operator * (unsigned long int integer)const;
	big_integer& operator *= (unsigned long int integer);
	big_integer operator * (signed long int integer)const;
	big_integer& operator *= (signed long int integer);

	big_integer abs()const;

	big_integer operator / (const big_integer& integer)const;
	big_integer& operator /= (const big_integer& integer);
	big_integer operator / (unsigned long int integer)const;
	big_integer& operator /= (unsigned long int integer);

	big_integer operator % (const big_integer& integer)const;
	big_integer& operator %= (const big_integer& integer);
	big_integer operator % (unsigned long int integer)const;
	big_integer& operator %= (unsigned long int integer);

	std::pair<big_integer,big_integer> div(const big_integer& integer)const;
	std::pair<big_integer,big_integer> div(unsigned long int integer)const;

	big_integer mod(const big_integer& integer)const;
	big_integer mod(unsigned long int integer)const;
	big_integer mod_inverse(const big_integer& integer)const;
	big_integer mod_pow(const big_integer& exponent, const big_integer& modulus)const;

	enum PrimeProbability {
		DEFINITELY_COMPOSITE = 0,
		PROBABLY_PRIME       = 1,
		DEFINITELY_PRIME     = 2
	};
	PrimeProbability is_probable_prime(int reps)const;
	big_integer next_prime()const;

	big_integer gcd(const big_integer& integer)const;
	big_integer gcd(unsigned long int integer)const;
	big_integer lcm(const big_integer& integer)const;
	big_integer lcm(unsigned long int integer)const;

	int compare(const big_integer& integer)const;
	int compare(unsigned long int integer)const;
	int compare(signed long int integer)const;
	int compare(double number)const;

	inline bool operator <(const big_integer& integer)const{return compare(integer)<0;}
	inline bool operator <(unsigned long int integer)const{return compare(integer)<0;}
	inline bool operator <(signed long int integer)const{return compare(integer)<0;}
	inline bool operator <(double number)const{return compare(number)<0;}

	inline bool operator <=(const big_integer& integer)const{return compare(integer)<=0;}
	inline bool operator <=(unsigned long int integer)const{return compare(integer)<=0;}
	inline bool operator <=(signed long int integer)const{return compare(integer)<=0;}
	inline bool operator <=(double number)const{return compare(number)<=0;}

	inline bool operator ==(const big_integer& integer)const{return compare(integer)==0;}
	inline bool operator ==(unsigned long int integer)const{return compare(integer)==0;}
	inline bool operator ==(signed long int integer)const{return compare(integer)==0;}
	inline bool operator ==(double number)const{return compare(number)==0;}

	inline bool operator !=(const big_integer& integer)const{return compare(integer)!=0;}
	inline bool operator !=(unsigned long int integer)const{return compare(integer)!=0;}
	inline bool operator !=(signed long int integer)const{return compare(integer)!=0;}
	inline bool operator !=(double number)const{return compare(number)!=0;}

	inline bool operator >=(const big_integer& integer)const{return compare(integer)>=0;}
	inline bool operator >=(unsigned long int integer)const{return compare(integer)>=0;}
	inline bool operator >=(signed long int integer)const{return compare(integer)>=0;}
	inline bool operator >=(double number)const{return compare(number)>=0;}

	inline bool operator >(const big_integer& integer)const{return compare(integer)>0;}
	inline bool operator >(unsigned long int integer)const{return compare(integer)>0;}
	inline bool operator >(signed long int integer)const{return compare(integer)>0;}
	inline bool operator >(double number)const{return compare(number)>0;}

	int compare_absolute(const big_integer& integer)const;
	int compare_absolute(unsigned long int integer)const;
	int compare_absolute(double number)const;

	int signum()const;

	bool odd()const;
	bool even()const;

	big_integer operator & (const big_integer& integer)const;
	big_integer& operator &= (const big_integer& integer);
	big_integer operator | (const big_integer& integer)const;
	big_integer& operator |= (const big_integer& integer);
	big_integer operator ^ (const big_integer& integer)const;
	big_integer& operator ^= (const big_integer& integer);
	big_integer operator ~ ()const;

	bool get(size_t pos)const;
	inline bool test(size_t pos)const {return get(pos);}
	big_integer& set(size_t pos, bool value = true );
	big_integer& reset(size_t pos);
	big_integer& flip(size_t pos);
	unsigned long int count()const;

	void swap(big_integer& integer);

	template<typename T> void assign(const T* ptr, size_t count, WordOrder order = WORD_MOST_SIGNIFICANT_FIRST, Endianess endian = NATIVE, size_t nails = 0)
	{
		mpz_import(__integ, count, (int)order, sizeof(T), (int)endian, nails, ptr);
	}

	template<typename T> void assign(const std::vector<T>& vec, WordOrder order = WORD_MOST_SIGNIFICANT_FIRST, Endianess endian = NATIVE, size_t nails = 0)
	{
		assign(vec.data(), vec.size(), order, endian, nails);
	}

	template<typename T, std::size_t N > void assign(const std::array<T,N>& arr, WordOrder order = WORD_MOST_SIGNIFICANT_FIRST, Endianess endian = NATIVE, size_t nails = 0)
	{
		assign(arr.data(), arr.size(), order, endian, nails);
	}

	template<typename T> std::vector<T> get_vector(WordOrder order = WORD_MOST_SIGNIFICANT_FIRST, Endianess endian = NATIVE, size_t nails = 0) const
	{
		size_t size = sizeof(T);
		size_t numb = 8*size - nails;
		size_t count = (mpz_sizeinbase(__integ, 2) + numb-1) / numb;
		std::vector<T> vec(count);
		mpz_export(vec.data(), &count, (int)order, size, (int)endian, nails, __integ);
		return vec;
	}

private:
	mpz_t __integ;
};

}} // namespace cxy::math

namespace std
{
	template<> inline void swap(cxy::math::big_integer& integer1, cxy::math::big_integer& integer2)
	{
		integer1.swap(integer2);
	}

	// TODO Add global comparison operators
	// TODO Add streaming operators

} // namespace std

#endif // _MATH_BIG_INTEGER_HPP_
