#include "plugin.hpp"

pattern_maker::pattern_maker() {
	msg("PatternMaker: Loaded successfully.\n");
}

pattern_maker::~pattern_maker() {
	msg("PatternMaker: Unloaded successfully.\n");
}

bool pattern_maker::run(size_t arg) {
	std::vector<uint8_t> bytes = {};
	std::vector<uint8_t> mask = {};
	int offset = {};

	ea64_t min_ea = inf_get_min_ea();
	ea64_t max_ea = inf_get_max_ea();

	msg("PatternMaker: Creating a signature, please wait...\n");

	if (arg == (size_t)-1) {
		PLUGIN.flags |= PLUGIN_UNL;
		return false;
	}

	auto address = get_screen_ea();
	if (!address) {
		msg("PatternMaker: Selected address is not valid.\n");
		return false;
	}

	if (!can_decode(address)) {
		msg("PatternMaker: Cannot decode this instruction.\n");
		return false;
	}
	
	for (int i = 0; i < 0x64; i++)
	{
		insn_t instruction{};
		if (decode_insn(&instruction, address + offset) == 0) {
			msg("PatternMaker: Cannot decode instruction @ 0x%p!\n", address + offset);
			break;
		}

		for (int j = 0; j < instruction.size; ++j)
			bytes.emplace_back(get_byte(instruction.ea + j));

		std::vector<uint8_t> instr_mask(instruction.size, 1);

		for (const auto& op : instruction.ops) {
			if (op.type == o_void)
				break;

			if (op.type != o_reg && op.type != o_phrase && op.type != o_displ) {
				std::fill(instr_mask.begin() + op.offb, instr_mask.end(), 0);
				break;
			}
		}

		instr_mask[0] = 1;
		std::copy(instr_mask.begin(), instr_mask.end(), std::back_inserter(mask));

		if (bin_search(min_ea, address, bytes.data(), mask.data(), bytes.size(), BIN_SEARCH_FORWARD) == BADADDR)
			if (bin_search(address + bytes.size(), max_ea, bytes.data(), mask.data(), bytes.size(), BIN_SEARCH_FORWARD) == BADADDR)
				break;

		offset += instruction.size;
	}

	std::string pattern{};
	for (int i = 0; i < bytes.size(); ++i) {
		if (mask[i] == 1) {
			std::array<char, 3> byte{};
			sprintf_s(byte.data(), byte.size(), "%02X", bytes[i]);

			pattern += byte.data();
			pattern += " ";
		}
		else pattern += "? ";
	}

	if (pattern.empty()) {
		msg("PatternMaker: Could not make a pattern for this instruction.\n");
		return false;
	}
	
	pattern = pattern.substr(0, pattern.length() - 1);
	msg("PatternMaker: Unique Pattern -> %s\n", pattern.c_str());

	return true;
}