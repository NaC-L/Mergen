#pragma once
#include "includes.h"

FunctionPass* create_nacibaba_replace_load_with_store_pass();

FunctionPass* create_nacibaba_replace_load_from_memory(LPVOID binaryBase, ZyanU8* data);


FunctionPass* create_nacibaba_replace_load_with_store_pass_final();

FunctionPass* createIntToPtrToAllocaPass();
FunctionPass* create_RemoveStackPushes();

FunctionPass* CreateIntToPtrStackDSEPass();