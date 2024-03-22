// lifter.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "includes.h"
#include "LLVM-init.h"
#include "Semantics.h"
#include "OperandUtils.h"
#include "ROPdetection.h"
#include "OperandUtils.h"
#include "nt/nt_headers.hpp"
#include <cstdlib>
#include <fstream>

#define _CRTDBG_MAP_ALLOC
// Function to disassemble and convert


// plan:
// 1- Handle operands, get set etc. (framework for handling instructions)  -done
// ^^^dont forget properly getting highest register
//
// 1a- Initialize calling stuff, registers - done
// 1b- Get and set registers done
// ^^^dont forget size conversions
// ^^^most of the stuff that elongates the reversing process is writing stuff into memory.
//
// 2- Handle instructions.  - semi done , added few instructions
//
// 3- Handle blocks or optimization - working on blocks
//
// 4- Handle blocks or optimization
//


vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > added_blocks_addresses;
uintptr_t original_address = 0;

// first of all, this function is UGLY af, so I'm sorry you are reading this.
void asm_to_zydis_to_lift(LLVMContext& context, IRBuilder<>& builder, ZyanU8* data, ZyanU64 runtime_address, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses, Function* function, ZyanU64 file_base) {

    // run the loop until we have a reason to end, I believe this should've been removed but its there :trollface:
    bool run = 1;
    while (run) {

        // blockAddresses contains the blocks we want to work on. If there is no block we want to work on, end the loop.
        while (blockAddresses->size() > 0) {

            // find the real address in memory of where we want to continue parsing
            runtime_address = get<0>(blockAddresses->back());
            uintptr_t offset = address_to_mapped_address((void*)file_base, runtime_address);
#ifdef _DEVELOPMENT
            cout << "runtime_addr: " << runtime_address << " offset:" << offset << " byte there: 0x" << (int)*(uint8_t*)(file_base + offset) << endl;
            cout << "offset: " << offset << " file_base?: " << original_address << " runtime: " << runtime_address << endl;
#endif






            // not sure what it was supposed to do
            added_blocks_addresses.push_back(blockAddresses->back());
            // set the LLVM builder to work on bb
            builder.SetInsertPoint(get<1>(blockAddresses->back()));



            // we want to store the register list because its SSA.
            setRegisterList(get<2>(blockAddresses->back()));
            // a very simplified representation why:
            //
            // mov ecx, 10 --- %ecx_0 = 10
            // test eax, eax --- if (!eax) jump branch2;
            // je branch2:
            //
            // branch1:
            // add ecx, 10 --- %ecx_1 = %ecx_0 + 10
            // ret --- ret i64 %ecx_1
            // branch2:
            // sub ecx, 10 --- %ecx_2 = %ecx_0 - 10
            // ret -- ret i64 %ecx_2
            //
            // if we hadn't store the registers then branch
            // branch2 would thought we still operate on %ecx_1 and since it's in a different branch, it wouldn't work


            // we are working on this block, so remove it from vector
            blockAddresses->pop_back();

            // this is for memory accesses to the binary
            initDetections((void*)file_base, data);
            initBases2((void*)file_base, data);
            size_t last_value;

            //idk?
            bool run = 1;

            //sanity check
            if (!blockAddresses->empty()) {
                last_value = get<0>(blockAddresses->back());
            }
            else {
                // Handle error or set a default value to last_value
                last_value = 0;  // or some other appropriate value or action
            }

            // more loops :trollface:
            ZydisDisassembledInstruction instruction;
            // this loop is responsible of parsing asm into zydis then LLVM.
            for (; run && runtime_address > 0; )
            {
                //the function we know and we love
                ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, runtime_address, data + offset, 15, &instruction);

                if (
                    (blockAddresses->size() == 0 ||
                        (last_value == get<0>(blockAddresses->back()))))
                {

                    // Print current instruction.

#ifdef _DEVELOPMENT
                    cout << instruction.text << "\n";
                    cout << "runtime: " << runtime_address << "\n";
#endif
                    instruction.runtime_address += instruction.info.length;


                    // WHERE THE MAGIC REALLY HAPPENS.
                    liftInstruction(context, builder, instruction, blockAddresses, &run);

                    // i dont remember.
                    offset += instruction.info.length;
                    runtime_address += instruction.info.length;

                    for (auto& b_address : added_blocks_addresses) {
                        if (get<0>(b_address) - file_base == offset) {
                            builder.CreateBr(get<1>(b_address));
                            builder.SetInsertPoint(get<1>(b_address));
                            run = 0;
                            break;
                        }
                    }

                }
                else
                {
                    break;
                }
            }

        }
        run = 0;

        // print the function to a file
        llvm::ValueToValueMapTy VMap;
        std::string Filename = "output_noopts.ll";
        std::error_code EC;
        llvm::raw_fd_ostream OS(Filename, EC);

        function->print(OS, nullptr);

    }
}



void InitFunction_and_LiftInstructions(ZyanU8* data, ZyanU64 runtime_address, uintptr_t file_base) {
    ZydisDecoder decoder;
    ZydisFormatter formatter;

    // Initialize decoder and formatter.
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    // initialize llvm context and module
    LLVMContext context;
    string mod_name = "my_lifting_module";
    llvm::Module lifting_module = llvm::Module(mod_name.c_str(), context);


    // initialize arguments
    std::vector<llvm::Type*> argTypes;
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getInt64Ty(context)); // 16 regs
    argTypes.push_back(llvm::Type::getVoidTy(context)->getPointerTo()); // 1 off because rsp

    auto functionType = llvm::FunctionType::get(llvm::Type::getInt64Ty(context), argTypes, 0);


    // initialize function
    string function_name = "main";
    auto function = llvm::Function::Create(functionType, llvm::Function::ExternalLinkage, function_name.c_str(), lifting_module);

    // initialize BB(basic block)
    string block_name = "entry";
    auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), function);
    llvm::IRBuilder<> builder = llvm::IRBuilder<>(bb);

    // "link" the arguments to a register map
    auto RegisterList = InitRegisters(context, builder, function, runtime_address);

    ZydisDisassembledInstruction instruction;



    // this works, but its ugly.
    std::shared_ptr<std::vector<std::tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*>>>> blockAddresses = std::make_shared<std::vector<std::tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*>>>>();

    blockAddresses->push_back(make_tuple(runtime_address, bb, RegisterList));

    // WHERE MAGIC HAPPENS.
    asm_to_zydis_to_lift(context, builder, (uint8_t*)file_base, runtime_address, blockAddresses, function, file_base);


    // dump the result to output.ll
    std::string Filename = "output.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);

    if (EC) {
        llvm::errs() << "Could not open file: " << EC.message();
        return;
    }

    lifting_module.print(OS, nullptr);
    // Close the output stream
    OS.flush();


    return;
}

int main(int argc, char* argv[])
{
    auto start = std::chrono::high_resolution_clock::now();

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <filename> <startAddr>" << std::endl;
        return 1;
    }

    const char* filename = argv[1];
    uint64_t startAddr = std::stoull(argv[2], nullptr, 0);

    std::ifstream ifs(filename, std::ios::binary);
    if(!ifs.is_open()) {
        std::cout << "Failed to open the file." << std::endl;
        return 1;
    }

    ifs.seekg(0, std::ios::end);
    std::vector<uint8_t> fileData(ifs.tellg());
    ifs.seekg(0, std::ios::beg);

    if(!ifs.read((char*)fileData.data(), fileData.size())) {
        std::cout << "Failed to read the file." << std::endl;
        return 1;
    }
    ifs.close();

    auto fileBase = fileData.data();

    // Parse the PE headers
    auto dosHeader = (win::dos_header_t*)fileBase;
    auto ntHeaders = (win::nt_headers_x64_t*)(fileBase + dosHeader->e_lfanew);
    auto sectionHeader = ntHeaders->get_sections();
    auto ADDRESS = ntHeaders->optional_header.image_base;
    uintptr_t RVA = static_cast<uintptr_t>(startAddr - ADDRESS);
    uintptr_t fileOffset = RvaToFileOffset(ntHeaders, RVA);
    uint8_t* dataAtAddress = fileBase + fileOffset;
    cout << hex << "0x" << (int)*dataAtAddress << endl;
    original_address = ADDRESS;
    cout << "address: " << ADDRESS << " filebase: " << (uintptr_t)fileBase << " fOffset: " << fileOffset << " RVA: " << RVA << endl;


    // important part here.
    InitFunction_and_LiftInstructions(dataAtAddress, startAddr, (uintptr_t)fileBase);



    // ending...
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
        elapsed).count();
    cout << "\n" << dec << microseconds << " microsecond has past";
}
