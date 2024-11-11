#pragma once
#include <algorithm>
#include <iterator>
#include <array>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <funcs.hpp>

class pattern_maker : plugmod_t
{
public:
	static plugmod_t* idaapi init(void) {
		return new pattern_maker();
	}

	pattern_maker();
	virtual ~pattern_maker();

	virtual void term();
	virtual bool idaapi run(size_t arg) override;
};