#pragma once
#include "includes.h"

void liftInstruction(IRBuilder<>& builder,
                     ZydisDisassembledInstruction& instruction,
                     shared_ptr<vector<BBInfo>> blockAddresses, bool& run);