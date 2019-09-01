/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/math-big-integer.cpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include "math/big-integer.hpp"


TEST_CASE( "Signed big integer", "[io]" ) {
    using namespace cxy;

	math::big_integer integer((signed long int)25);

	REQUIRE( integer.to_signed_int()==25 );

	integer = (signed long int)-42;

	REQUIRE( integer.to_signed_int()==-42 );
}

TEST_CASE( "Unsigned big integer", "[io]" ) {
    using namespace cxy;

	math::big_integer integer((unsigned long int)25);

	REQUIRE( integer.to_unsigned_int()==25 );

	integer = (unsigned long int)42;

	REQUIRE( integer.to_unsigned_int()==42 );
}

TEST_CASE( "Float big integer", "[io]" ) {
    using namespace cxy;

	math::big_integer integer(25.42);

	REQUIRE( integer.to_float()==25.0 );

	integer = (double)-42.25;

	REQUIRE( integer.to_double()==-42.0 );
}
