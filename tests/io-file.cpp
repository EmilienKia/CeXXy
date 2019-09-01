/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/io-file.cpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include <random>
#include <list>

#include "io/file.hpp"


TEST_CASE( "File stream", "[io]" ) {
    using namespace cxy;

	std::vector<std::uint8_t> mem {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

	{
		io::file_output_stream out("test.tst");
		out.write(12);
		io::file_output_stream out2(out.get_file_descriptor());
		out.write(mem.data(), 10);
		out.flush();
		out2.flush();
		out.close();
		out2.close();
	}

	{
		io::file_input_stream in("test.tst");

        // First byte
		REQUIRE( in.read()==12 );

		std::uint8_t res[8];
        // Read fully 8 bytes
		REQUIRE( in.read(res, 8) == 8 );
		for(int i = 0; i < 8; i++)
		{
			REQUIRE(res[i]==mem[i] );
		}

		io::file_input_stream in2(in.get_file_descriptor());

        // Read partially 8 bytes
		REQUIRE(in2.read(res, 8) == 2 );
		for(int i = 0; i < 2; i++)
		{
			REQUIRE( res[i]==mem[i+8] );
		}

		in.close();
		in2.close();

	}

}
