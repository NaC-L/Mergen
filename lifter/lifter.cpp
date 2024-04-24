

#include "includes.h"
#include "LLVM-init.h"
#include "Semantics.h"
#include "OperandUtils.h"
#include "GEPTracker.h"
#include "PathSolver.h"
#include "OperandUtils.h"
#include "nt/nt_headers.hpp"
#include <cstdlib>
#include <fstream>

#define _CRTDBG_MAP_ALLOC

vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > added_blocks_addresses;
uintptr_t original_address = 0;


void asm_to_zydis_to_lift(LLVMContext& context, IRBuilder<>& builder, ZyanU8* data, ZyanU64 runtime_address, shared_ptr<vector< tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*> > > > blockAddresses, Function* function, ZyanU64 file_base) {

    
    bool run = 1;
    while (run) {

        
        while (blockAddresses->size() > 0) {

            
            runtime_address = get<0>(blockAddresses->back());
            uintptr_t offset = address_to_mapped_address((void*)file_base, runtime_address);
#ifdef _DEVELOPMENT
            cout << "runtime_addr: " << runtime_address << " offset:" << offset << " byte there: 0x" << (int)*(uint8_t*)(file_base + offset) << endl;
            cout << "offset: " << offset << " file_base?: " << original_address << " runtime: " << runtime_address << endl;
#endif
            
            added_blocks_addresses.push_back(blockAddresses->back());
            
            builder.SetInsertPoint(get<1>(blockAddresses->back()));
            
            setRegisterList(get<2>(blockAddresses->back()));
            
            blockAddresses->pop_back();

            BinaryOperations::initBases((void*)file_base, data);
            size_t last_value;

            bool run = 1;

            
            if (!blockAddresses->empty()) {
                last_value = get<0>(blockAddresses->back());
            }
            else {
                
                last_value = 0;  
            }

            
            ZydisDisassembledInstruction instruction;
            
            for (; run && runtime_address > 0; )
            {
                
                ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, runtime_address, data + offset, 15, &instruction);

                if (
                    (blockAddresses->size() == 0 ||
                        (last_value == get<0>(blockAddresses->back()))))
                {

                    

#ifdef _DEVELOPMENT
                    outs() << instruction.text << "\n";
                    outs() << "runtime: " << runtime_address << "\n";
                    outs().flush();
#endif
                    instruction.runtime_address += instruction.info.length;


                    
                    liftInstruction(context, builder, instruction, blockAddresses, &run);

                    
                    offset += instruction.info.length;
                    runtime_address += instruction.info.length;

                    // whats the purpose of this ????
                    // maybe change it to a queue
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

        

    }
}



void InitFunction_and_LiftInstructions(ZyanU8* data, ZyanU64 runtime_address, uintptr_t file_base, shared_ptr<Module> lifting_module) {
    ZydisDecoder decoder;
    ZydisFormatter formatter;
    LLVMContext& context = lifting_module->getContext();

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);




    std::vector<llvm::Type*> argTypes;
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::Type::getInt64Ty(context));
    argTypes.push_back(llvm::PointerType::get(context, 0));

    auto functionType = llvm::FunctionType::get(llvm::Type::getInt64Ty(context), argTypes, 0);



    string function_name = "main";
    auto function = llvm::Function::Create(functionType, llvm::Function::ExternalLinkage, function_name.c_str(), lifting_module.get());


    string block_name = "entry";
    auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), function);
    llvm::IRBuilder<> builder = llvm::IRBuilder<>(bb);


    auto RegisterList = InitRegisters(context, builder, function, runtime_address);

    ZydisDisassembledInstruction instruction;


    std::shared_ptr<std::vector<std::tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*>>>> blockAddresses = std::make_shared<std::vector<std::tuple<uintptr_t, BasicBlock*, unordered_map<int, Value*>>>>();

    blockAddresses->push_back(make_tuple(runtime_address, bb, RegisterList));

    asm_to_zydis_to_lift(context, builder, (uint8_t*)file_base, runtime_address, blockAddresses, function, file_base);



    std::string Filename = "output.ll";
    std::error_code EC;
    llvm::raw_fd_ostream OS(Filename, EC);

    if (EC) {
        llvm::errs() << "Could not open file: " << EC.message();
        return;
    }

    lifting_module->print(OS, nullptr);

    
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



    LLVMContext context;
    string mod_name = "my_lifting_module";
    shared_ptr<Module> lifting_module = std::make_shared<Module>(mod_name.c_str(), context);
    
    InitFunction_and_LiftInstructions(dataAtAddress, startAddr, (uintptr_t)fileBase, lifting_module);



    
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
        elapsed).count();
    cout << "\n" << dec << microseconds << " microsecond has past" << endl;
}
