#include "includes.h"

// this file is where helper functions reside.

void* file_base_g_operand;
ZyanU8* data_g_operand;

void initBases2(void* file_base, ZyanU8* data) {
	file_base_g_operand = file_base;
	data_g_operand = data;
}



unordered_map<int,Value*> RegisterList;
unordered_map<Flag, Value*> FlagList;

IntegerType* getIntSize(int size, LLVMContext& context) {
	switch (size) {

	case 1: {
		return llvm::Type::getInt1Ty(context);
	}
	case 8: {
		return llvm::Type::getInt8Ty(context);
	}

	case 16: {
		return llvm::Type::getInt16Ty(context);
	}

	case 32: {
		return llvm::Type::getInt32Ty(context);
	}

	case 64: {
		return llvm::Type::getInt64Ty(context);
	}

	case 128: {
		return llvm::Type::getInt128Ty(context);
	}

    default: {
        return llvm::Type::getIntNTy(context, size);
    }

	}
}


void Init_Flags(LLVMContext& context, IRBuilder<>& builder) {

	auto zero = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt1Ty(context), 0);

	FlagList[FLAG_CF] = zero;
	FlagList[FLAG_PF] = zero;
	FlagList[FLAG_AF] = zero;
	FlagList[FLAG_ZF] = zero;
	FlagList[FLAG_SF] = zero;
	FlagList[FLAG_TF] = zero;
	FlagList[FLAG_IF] = zero;
	FlagList[FLAG_DF] = zero;
	FlagList[FLAG_OF] = zero;
}

// responsible of operations on RFLAG
Value* setFlag(LLVMContext& context, IRBuilder<>& builder, Flag flag, Value* newValue = nullptr) {
	return FlagList[flag] = newValue;

}
Value* getFlag(LLVMContext& context, IRBuilder<>& builder, Flag flag) {
	return FlagList[flag];
}





// instead of 1 variable
// have multiple variables that correspond to the flags

void Init_Flags2(LLVMContext& context, IRBuilder<>& builder) {


	auto zero = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 0);
	auto value = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 2); // 2nd bit is reserved and always true

	auto flags = RegisterList[ZYDIS_REGISTER_RFLAGS];

	auto new_flag = builder.CreateAdd(zero, value);

	RegisterList[ZYDIS_REGISTER_RFLAGS] = new_flag;
}


//...
unordered_map<int, Value*> getRegisterList() {
	return RegisterList;
}

//...
void setRegisterList(unordered_map<int, Value*> newRegisterList) {
	RegisterList = newRegisterList;
}



Value* memoryAlloc;

void initMemoryAlloc(Value* allocArg) {
	memoryAlloc = allocArg;
}

unordered_map<int, Value*> InitRegisters(LLVMContext& context, IRBuilder<>& builder,Function* function, ZyanU64 rip) {

	int zydisRegister = ZYDIS_REGISTER_RAX; // Replace with desired key

	auto argEnd = function->arg_end();
	for (auto argIt = function->arg_begin(); argIt != argEnd; ++argIt) {

		if ((zydisRegister == ZYDIS_REGISTER_RSP) || (zydisRegister == ZYDIS_REGISTER_ESP)) {
			// we dont want to register Stack Pointer register as an argument, because then it confuses llvm
			zydisRegister++;
			continue;
		}

		llvm::Argument* arg = &*argIt;
		arg->setName(ZydisRegisterGetString((ZydisRegister)zydisRegister));
		// Check if it's the last argument, if its last argument, create a FLAGS argument where we store flags. probably create a struct for it instead
		if (std::next(argIt) == argEnd) {
			arg->setName("memory");
			memoryAlloc = arg;
		}
		else {
			RegisterList[(ZydisRegister)zydisRegister] = arg;
			zydisRegister++;
		}
	}

	// Initialize flag value, it will be always 2
	Init_Flags(context,builder);



	auto zero = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), 0);
	auto value = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), rip);

	// initialize xIP value, should be function start, its here for stuff like getting .data or calling functions
	auto new_rip = builder.CreateAdd(zero, value);
	// move initialized value into map
	RegisterList[ZYDIS_REGISTER_RIP] = new_rip;


	// initialize xSP value, as said, when xSP is not a defined value, optimizations get messy.
	auto stackvalue = (ConstantInt*)llvm::ConstantInt::getSigned(llvm::Type::getInt64Ty(context), STACKP_VALUE);
	auto new_stack_pointer = builder.CreateAdd(stackvalue, zero);
	// move initialized value into map
	RegisterList[ZYDIS_REGISTER_RSP] = new_stack_pointer;

	return RegisterList;
}

// get the highest byte
// basically should be 0xFF00
Value* GetValueFromHighByteRegister(LLVMContext& context, IRBuilder<>& builder, int reg) {


	Value* fullRegisterValue = RegisterList[ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,(ZydisRegister)reg) ];  // Assume we fetch the 64-bit RAX, RCX, etc.

	// Right-shift to bring the high-byte to the least-significant position
	Value* shiftedValue = builder.CreateLShr(fullRegisterValue, 8,"highreg");

	// Mask out other bits to extract the high byte
	Value* highByteValue = builder.CreateAnd(shiftedValue, 0xFF);

	return highByteValue;
}


// this function will probably cause issues in the future
void SetRFLAGSValue(LLVMContext& context, IRBuilder<>& builder, Value* value) {

	for (int flag = FLAG_CF; flag++; flag < FLAGS_END) {
		int shiftAmount = flag;
		Value* shiftedFlagValue = builder.CreateLShr(value, ConstantInt::get(Type::getInt64Ty(context), shiftAmount) ); // Value >> flag
		auto flagValue = builder.CreateTrunc(shiftedFlagValue, Type::getInt1Ty(context)); // i64 ...0001 to 1
		setFlag(context,builder,(Flag)flag,flagValue);
		// shl and or flags to have one big flag
	}
	return ;
}

Value* GetRFLAGSValue(LLVMContext& context, IRBuilder<>& builder) {
	Value* rflags = ConstantInt::get(Type::getInt64Ty(context), 0); // Assuming a 64-bit value for simplicity

	for (int flag = FLAG_CF; flag++; flag < FLAGS_END) {
		Value* flagValue = getFlag(context, builder, (Flag)flag);
		int shiftAmount = flag; 
		Value* shiftedFlagValue = builder.CreateShl(flagValue, ConstantInt::get(Type::getInt64Ty(context), shiftAmount));
		rflags = builder.CreateOr(rflags, shiftedFlagValue);
	}
	return rflags;
}

// responsible for retrieving latest llvm SSA value from a asm register
Value* GetRegisterValue(LLVMContext& context, IRBuilder<>& builder, int key) {
	// ZYDIS_REGISTER_RFLAGS is bugged and it will return ZYDIS_REGISTER_NONE

	if (key == ZYDIS_REGISTER_AH || key == ZYDIS_REGISTER_CH || key == ZYDIS_REGISTER_DH || key == ZYDIS_REGISTER_BH) {
		return GetValueFromHighByteRegister(context, builder, key);
	}


	int newKey = (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP) ? ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)key) : key;


	if (key == ZYDIS_REGISTER_RFLAGS) {
		return GetRFLAGSValue(context, builder);
	}

	/*
	if (RegisterList.find(newKey) == RegisterList.end()) {
		throw std::runtime_error("register not found"); exit(-1);
	}
	*/

	return RegisterList[newKey];

}






Value* SetValueToHighByteRegister(LLVMContext& context, IRBuilder<>& builder, int reg, Value* value) {
	int shiftValue = 8;

	// Convert key for high-byte registers to their 64-bit counterparts
	int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg);
	Value* fullRegisterValue = RegisterList[fullRegKey];

	// Ensure the value being shifted is of the correct type
	Value* eightBitValue = builder.CreateAnd(value, ConstantInt::get(value->getType(), 0xFF),"eight-bit");
	Value* shiftedValue = builder.CreateShl(eightBitValue, ConstantInt::get(value->getType(), shiftValue),"shl");

	// Create mask and clear the high-byte portion
	Value* mask = ConstantInt::get(Type::getInt64Ty(context), ~(0xFF << shiftValue));
	Value* clearedRegister = builder.CreateAnd(fullRegisterValue, mask,"clear-reg");

	shiftedValue = builder.CreateZExt(shiftedValue, fullRegisterValue->getType() );
	// Set the high-byte portion of the register
	Value* newRegisterValue = builder.CreateOr(clearedRegister, shiftedValue,"high_byte");

	return newRegisterValue;
}

// I dont remember the logic, however it should be related to this snippet:
// mov eax, 0x12345678
//--- eax = 0x12345678
//mov al,  0xFF
// --- eax = 0X123456FF
Value* SetValueToSubRegister(LLVMContext& context, IRBuilder<>& builder, int reg, Value* value) {
	// Convert key for sub-register to their 64-bit counterparts
	int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg);
	Value* fullRegisterValue = RegisterList[fullRegKey];

	// Mask the full register so that only the sub-register part is set to 0
	Value* maskedFullReg = builder.CreateAnd(fullRegisterValue, 0xFFFFFFFFFFFFFF00,"maskedreg");
	value = builder.CreateZExt(value, fullRegisterValue->getType());
	// Or the masked full register with the sub-register value to set the byte
	Value* updatedReg = builder.CreateOr(maskedFullReg, value,"newreg");

	// Store the updated value back to the full register (if necessary)
	// e.g. RegisterList[fullRegKey] = updatedReg;

	return updatedReg;


}

// same as above but for 16 bits
Value* SetValueToSubRegister2(LLVMContext& context, IRBuilder<>& builder, int reg, Value* value) {
	// Convert key for sub-register to their 64-bit counterparts
	int fullRegKey = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)reg);
	Value* fullRegisterValue = RegisterList[fullRegKey];

	// Mask the full register so that only the sub-register part is set to 0
	Value* maskedFullReg = builder.CreateAnd(fullRegisterValue, 0xFFFFFFFFFFFF0000, "maskedreg");
	value = builder.CreateZExt(value, fullRegisterValue->getType());
	// Or the masked full register with the sub-register value to set the byte
	Value* updatedReg = builder.CreateOr(maskedFullReg, value, "newreg");

	// Store the updated value back to the full register (if necessary)
	// e.g. RegisterList[fullRegKey] = updatedReg;

	return updatedReg;


}

// responsible for setting a LLVM SSA Value
void SetRegisterValue(LLVMContext& context, IRBuilder<>& builder, int key, Value* value) {
    if (
        (key == ZYDIS_REGISTER_AH || key == ZYDIS_REGISTER_CH || key == ZYDIS_REGISTER_DH || key == ZYDIS_REGISTER_BH)) { // handling all 8 sub-registers
        value = SetValueToSubRegister(context, builder, key, value);


    }

	if ( ( (key >= ZYDIS_REGISTER_R8B) && (key <= ZYDIS_REGISTER_R15B) ) || ((key >= ZYDIS_REGISTER_AL) && (key <= ZYDIS_REGISTER_BL)) || ((key >= ZYDIS_REGISTER_SPL) && (key <= ZYDIS_REGISTER_DIL))) {

		value = SetValueToSubRegister(context, builder, key, value);
	}

	if (((key >= ZYDIS_REGISTER_AX) && (key <= ZYDIS_REGISTER_R15W))) {
		value = SetValueToSubRegister2(context, builder, key, value);
	}

	
	if (key == ZYDIS_REGISTER_RFLAGS) {
		SetRFLAGSValue(context, builder, value);
		return;
	}

    int newKey = (key != ZYDIS_REGISTER_RFLAGS) && (key != ZYDIS_REGISTER_RIP) ? ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, (ZydisRegister)key) : key;

    RegisterList[newKey] = value;
}


// responsible for finding values of addresses ( [] )
Value* GetEffectiveAddress(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, int possiblesize) {
	// First, compute the effective address.
	Value* effectiveAddress = nullptr;

	// Assuming op.mem.base is the base register and op.mem.index is the index register.
	// Also assuming op.mem.scale is the scale factor and op.mem.disp is the displacement.

	Value* baseValue = nullptr;
	if (op.mem.base != ZYDIS_REGISTER_NONE) {
		baseValue = GetRegisterValue(context, builder, op.mem.base);
		baseValue = builder.CreateZExtOrTrunc(baseValue,getIntSize( ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64,op.mem.base), context) );
	}

	Value* indexValue = nullptr;
	if (op.mem.index != ZYDIS_REGISTER_NONE) {
		indexValue = GetRegisterValue(context, builder, op.mem.index);
		if (op.mem.scale > 1) {
			Value* scaleValue = ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
			indexValue = builder.CreateZExt(indexValue, Type::getInt64Ty(context));
			indexValue = builder.CreateMul(indexValue, scaleValue,"gea");
		}
	}

	if (baseValue && indexValue) {
		indexValue = builder.CreateZExtOrTrunc(indexValue, baseValue->getType(),"indexValue");
		effectiveAddress = builder.CreateAdd(baseValue, indexValue,"bvalueandindexvaluelea");
	}
	else if (baseValue) {
		effectiveAddress = baseValue;
	}
	else if (indexValue) {
		effectiveAddress = indexValue;
	}
	else {
		effectiveAddress = ConstantInt::get(Type::getInt64Ty(context), 0);
	}

	if (op.mem.disp.has_displacement) {

		Value* dispValue = ConstantInt::get(Type::getInt64Ty(context), (int)(op.mem.disp.value));
		effectiveAddress = builder.CreateAdd(effectiveAddress, dispValue,"effective_address");
	}

	return effectiveAddress;
}
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Value.h"
#include <vector>
#include <cassert>

using namespace llvm;

class ValueByteReference {
public:
	Value* value;
	short byteOffset;

	ValueByteReference(Value* val, short offset) : value(val), byteOffset(offset) {}
};

class lifterMemoryBuffer {
public:
	std::vector<ValueByteReference*> buffer; // Now storing pointers to ValueByteReference

	lifterMemoryBuffer() : buffer(STACKP_VALUE+0x100, nullptr) {} // Initialize with a default size, all nullptrs

	~lifterMemoryBuffer() {
		// Clean up dynamically allocated ValueByteReferences
		for (auto* ref : buffer) {
			delete ref;
		}
	}

	// addValueReference v = 0x12345678 at 0x0
	// v0 v1 v2 v3 =
	// when retrieved
	// v & 0xff + v & 0xff00 + v & 0xff0000 + v & 0xff000000

	void addValueReference(Value* value, unsigned address) {
		unsigned valueSizeInBytes = value->getType()->getIntegerBitWidth() / 8;
		for (unsigned i = 0; i < valueSizeInBytes; i++) {
			// Ensure the buffer is large enough
			delete buffer[address + i];
			// Create a new reference for each byte
			buffer[address + i] = new ValueByteReference(value, i);
		}
	}

	Value* retrieveCombinedValue(llvm::IRBuilder<>& builder, unsigned startAddress, unsigned byteCount) {
		Value* result = nullptr;
		for (unsigned i = 0; i < byteCount; i++) {
			unsigned currentAddress = startAddress + i;
			if (currentAddress < buffer.size() && buffer[currentAddress] != nullptr) {
				auto* ref = buffer[currentAddress];
				llvm::Value* byteValue = extractByte(builder, ref->value, ref->byteOffset);
				if (!result) {
					result = builder.CreateZExt(byteValue, Type::getIntNTy(builder.getContext(), byteCount * 8));
				}
				else {
					llvm::Value* shiftedByteValue = builder.CreateShl(builder.CreateZExt(byteValue, Type::getIntNTy(builder.getContext(), byteCount*8) ), llvm::APInt(byteCount * 8, i * 8));
					result = builder.CreateAdd(result, shiftedByteValue);
				}
			}

		}
		return result;
	}

private:
	llvm::Value* extractByte(llvm::IRBuilder<>& builder, llvm::Value* value, unsigned byteOffset) {
		// Assuming the value is a 32-bit integer, adjust the shift amount based on the byte offset
		unsigned shiftAmount = byteOffset * 8;
		llvm::Value* shiftedValue = builder.CreateLShr(value, llvm::APInt(value->getType()->getIntegerBitWidth(), shiftAmount), "extractbyte");
		return builder.CreateTrunc(shiftedValue, Type::getInt8Ty(builder.getContext()));
	}
};


lifterMemoryBuffer globalBuffer;

// responsible for retrieving a value in SSA Value map
Value* GetOperandValue(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, int possiblesize) {

	auto type = getIntSize(possiblesize, context);

	switch (op.type) {
		case ZYDIS_OPERAND_TYPE_REGISTER: {
			Value* value = GetRegisterValue(context, builder, op.reg.value);



			auto opBitWidth = op.size;
			auto typeBitWidth = dyn_cast<IntegerType>(value->getType())->getBitWidth();
			auto new_value =
				builder.CreateZExtOrTrunc(value, type, "trunc");
			return new_value;
		}
		case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
			ConstantInt* val;
			if (op.imm.is_signed) {
				val = (ConstantInt*)llvm::ConstantInt::getSigned(type, op.imm.value.s);
			}
			else {
				val = llvm::ConstantInt::get(context, llvm::APInt(possiblesize, op.imm.value.u));
			}
			return val;
		}
		case ZYDIS_OPERAND_TYPE_MEMORY: {
			// First, compute the effective address.
			Value* effectiveAddress = nullptr;

			// Assuming op.mem.base is the base register and op.mem.index is the index register.
			// Also assuming op.mem.scale is the scale factor and op.mem.disp is the displacement.

			Value* baseValue = nullptr;
			if (op.mem.base != ZYDIS_REGISTER_NONE) {
				baseValue = GetRegisterValue(context, builder, op.mem.base);



				baseValue = builder.CreateZExt(baseValue, Type::getInt64Ty(context));
			}


			Value* indexValue = nullptr;
			if (op.mem.index != ZYDIS_REGISTER_NONE) {
				indexValue = GetRegisterValue(context,builder,op.mem.index);
				indexValue = builder.CreateSExt(indexValue, Type::getInt64Ty(context));
				if (op.mem.scale > 1) {
					Value* scaleValue = ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
					indexValue = builder.CreateMul(indexValue, scaleValue);
				}
			}

			if (baseValue && indexValue) {
				effectiveAddress = builder.CreateAdd(baseValue, indexValue,"bvalue_indexvalue");
			}
			else if (baseValue) {
				effectiveAddress = baseValue;
			}
			else if (indexValue) {
				effectiveAddress = indexValue;
			}
			else {
				effectiveAddress = ConstantInt::get(Type::getInt64Ty(context), 0);
			}

			if (op.mem.disp.has_displacement) {
				Value* dispValue = ConstantInt::get(Type::getInt64Ty(context), (int) (op.mem.disp.value) );
				effectiveAddress = builder.CreateAdd(effectiveAddress, dispValue,"memory_addr");
			}

			// Load the value from the computed address.
			Type* loadType = getIntSize(possiblesize,context); // Determine based on op.mem.size or some other attribute
			//Value* pointer = builder.CreateIntToPtr(effectiveAddress, loadType->getPointerTo());

			std::vector<Value*> indices;
			indices.push_back(effectiveAddress); // First index is always 0 in this context

			Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc, indices, "GEPLoadxd-");



			if (isa<ConstantInt>(effectiveAddress)) {
				ConstantInt* effectiveAddressInt = dyn_cast<ConstantInt>(effectiveAddress);
				if (!effectiveAddressInt) return nullptr;

				uintptr_t addr = effectiveAddressInt->getZExtValue();
				uintptr_t mappedAddr = address_to_mapped_address(file_base_g_operand, addr);

				unsigned byteSize = loadType->getIntegerBitWidth() / 8;
				uintptr_t tempValue;

				if (mappedAddr > 0) {
					std::memcpy(&tempValue, reinterpret_cast<const void*>(data_g_operand + mappedAddr), byteSize);

					APInt readValue(byteSize * 8, tempValue);
					Constant* newVal = ConstantInt::get(loadType, readValue);
					if (newVal)
					return newVal;
				}

				if (addr > 0 && addr < STACKP_VALUE) {

					auto newval = globalBuffer.retrieveCombinedValue(builder, addr, byteSize);
					if (newval)
					return newval;

				}


			}


			/*
			if (isa<ConstantExpr>(pointer)) {
				if (Value* MapValue = GetMemoryValueFromMap(pointer)) { // MMap
					 return builder.CreateZExtOrTrunc(MapValue, loadType);
				}
				if (Operator* op = dyn_cast<Operator>(pointer)) { // Binary
					if (ConstantInt* CI = dyn_cast<ConstantInt>(op->getOperand(0))) {
						uintptr_t addr = CI->getZExtValue();
						uintptr_t mappedAddr = address_to_mapped_address(file_base_g_operand, addr);
						//cout << "mapppedaddr: " << mappedAddr << " addr: " << addr << "\n";
						if (mappedAddr > 0) {
							unsigned byteSize = loadType->getIntegerBitWidth() / 8;

							uintptr_t tempvalue;
							std::memcpy(&tempvalue, reinterpret_cast<const void*>(data_g_operand + mappedAddr), byteSize);


							APInt readValue(byteSize * 8, tempvalue);
							Constant* newVal = ConstantInt::get(loadType, readValue);
							return newVal;

						}
					}
				}
			}
			*/

			return builder.CreateLoad(loadType, pointer);
		}
		default: {
			throw std::runtime_error("operand type not implemented"); exit(-1);
		}
	}

}

// overwrite the first value with second
Value* merge(LLVMContext& context, IRBuilder<>& builder, Value* existingValue, Value* newValue) {
	// Get the bit width of the existing and new values
	unsigned existingBitWidth = existingValue->getType()->getIntegerBitWidth();
	unsigned newBitWidth = newValue->getType()->getIntegerBitWidth();

	if (newBitWidth >= existingBitWidth) {
		// If the new value is the same size or larger, completely overwrite the existing value
		return newValue;
	}
	// If the new value is smaller, create a mask for the existing value and overwrite it
	// Calculate the mask to keep the upper bits of the existing value
	llvm::APInt maskAPInt = llvm::APInt::getHighBitsSet(existingBitWidth, existingBitWidth - newBitWidth);
	Value* mask = llvm::ConstantInt::get(context, maskAPInt);

	// Apply the mask to the existing value
	Value* maskedExistingValue = builder.CreateAnd(existingValue, mask, "maskedExistingValue");

	// Extend the new value to match the bit width of the existing value
	Value* extendedNewValue = builder.CreateZExt(newValue, existingValue->getType(), "extendedNewValue");

	// Combine the masked existing value with the extended new value
	return builder.CreateOr(maskedExistingValue, extendedNewValue, "mergedValue");

}


// responsible for setting a value in SSA Value map
Value* SetOperandValue(LLVMContext& context, IRBuilder<>& builder, ZydisDecodedOperand& op, Value* value) {

	switch (op.type) {
		case ZYDIS_OPERAND_TYPE_REGISTER: {
			GetRegisterValue(context, builder, op.reg.value);

			SetRegisterValue(context, builder, op.reg.value, value);
			break;

		}case ZYDIS_OPERAND_TYPE_MEMORY:		{
			// Compute the effective address, as before.
			Value* effectiveAddress = nullptr;

			// Assuming op.mem.base is the base register and op.mem.index is the index register.
			// Also assuming op.mem.scale is the scale factor and op.mem.disp is the displacement.
			// base = zext
			// index = sext
			// imm = sext
			Value* baseValue = nullptr;
			if (op.mem.base != ZYDIS_REGISTER_NONE) {
				baseValue = GetRegisterValue(context, builder, op.mem.base);
				baseValue = builder.CreateZExt(baseValue, Type::getInt64Ty(context));
			}

			Value* indexValue = nullptr;
			if (op.mem.index != ZYDIS_REGISTER_NONE) {
				indexValue = GetRegisterValue(context, builder, op.mem.index);
				indexValue = builder.CreateSExt(indexValue, Type::getInt64Ty(context),"areyouok");
				if (op.mem.scale > 1) {
					Value* scaleValue = ConstantInt::get(Type::getInt64Ty(context), op.mem.scale);
					indexValue = builder.CreateMul(indexValue, scaleValue, "mul_ea");
				}
			}

			if (baseValue && indexValue) {
				effectiveAddress = builder.CreateAdd(baseValue, indexValue,"bvalue_indexvalue_set");
			}
			else if (baseValue) {
				effectiveAddress = baseValue;
			}
			else if (indexValue) {
				effectiveAddress = indexValue;
			}
			else {
				effectiveAddress = ConstantInt::get(Type::getInt64Ty(context), 0);
			}

			if (op.mem.disp.value) {
				Value* dispValue = ConstantInt::get(Type::getInt64Ty(context), op.mem.disp.value);
				effectiveAddress = builder.CreateAdd(effectiveAddress, dispValue,"disp_set");
			}

			// Store the value to the computed address.
			Type* storeType = getIntSize(op.size, context); // Determine based on op.mem.size or some other attribute
			//Value* pointer = builder.CreateIntToPtr(effectiveAddress, storeType->getPointerTo());
			std::vector<Value*> indices;
			indices.push_back(effectiveAddress); // First index is always 0 in this context

			Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc,indices,"GEPSTORE");
			Value* store = builder.CreateStore(value, pointer);  // Ensure `valueToSet` matches the expected type


			if (isa<ConstantInt>(effectiveAddress) ) {

				ConstantInt* effectiveAddressInt = cast<ConstantInt>(effectiveAddress);
				ConstantInt* valueInt = cast<ConstantInt>(value);
				unsigned bitWidth = valueInt->getBitWidth();
				uint64_t dataValue = valueInt->getZExtValue();

				globalBuffer.addValueReference(valueInt, effectiveAddressInt->getZExtValue());
			}


			return store;
		}
		break;

		default: {
            printf("kurwa: %d\n", op.type);
			throw std::runtime_error("operand type not implemented"); exit(-1);
            return nullptr;
		}
	}

}


Value* getMemoryFromValue(LLVMContext& context, IRBuilder<>& builder, Value* value) {

	Type* storeType = value->getType(); // Determine based on op.mem.size or some other attribute
	//Value* pointer = builder.CreateIntToPtr(effectiveAddress, storeType->getPointerTo());
	std::vector<Value*> indices;
	indices.push_back(value); // First index is always 0 in this context

	Value* pointer = builder.CreateGEP(Type::getInt8Ty(context), memoryAlloc, indices, "GEPSTOREVALUE");

	return pointer;

}




Value* getFlag2(LLVMContext& context, IRBuilder<>& builder, Flag flag) {
	Value* rflag_var = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
	Value* position = ConstantInt::get(context, APInt(64, flag));
	// Create the '1 << position' value
	Value* one = ConstantInt::get(context, APInt(64, 1));
	Value* bit_position = builder.CreateShl(one, position, "getflag-shl");

	// Return if the bit at 'position' is set
	Value* and_result = builder.CreateAnd(rflag_var, bit_position, "getflag-and");
	return builder.CreateICmpNE(and_result, ConstantInt::get(context, APInt(64, 0)), "getflag-cmpne");
}

Value* setFlag2(LLVMContext& context, IRBuilder<>& builder, Flag flag, Value* newValue) {
	Value* rflag_var = GetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS);
	Value* position = ConstantInt::get(context, APInt(64, flag));
	// Create the '1 << position' value
	Value* one = ConstantInt::get(context, APInt(64, 1));
	Value* bit_position = builder.CreateShl(one, position);

	Value* inverse_mask = builder.CreateNot(bit_position);

	// Clear the flag at 'position' in the rflag_var
	Value* cleared_rflag = builder.CreateAnd(rflag_var, inverse_mask);

	// Shift the new value to the correct position
	Value* shifted_newValue = builder.CreateShl(builder.CreateZExtOrTrunc(newValue, Type::getInt64Ty(context)), position, "flagsetweird");
	shifted_newValue = builder.CreateOr(cleared_rflag, shifted_newValue, "setflag-or");
	SetRegisterValue(context, builder, ZYDIS_REGISTER_RFLAGS, shifted_newValue);
	return shifted_newValue;
}
