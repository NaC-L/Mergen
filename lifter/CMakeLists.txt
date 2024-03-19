cmake_minimum_required(VERSION 3.16.0 FATAL_ERROR)

set(CMAKE_SYSTEM_VERSION 10.0.22621.0 CACHE STRING "" FORCE)

project(lifter CXX)

################################################################################
# Set target arch type if empty. Visual studio solution generator provides it.
################################################################################
if(NOT CMAKE_VS_PLATFORM_NAME)
    set(CMAKE_VS_PLATFORM_NAME "x64")
endif()
message("${CMAKE_VS_PLATFORM_NAME} architecture in use")

if(NOT ("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64"))
    message(FATAL_ERROR "${CMAKE_VS_PLATFORM_NAME} arch is not supported!")
endif()

################################################################################
# Global configuration types
################################################################################
set(CMAKE_CONFIGURATION_TYPES
    "Debug"
    "Release"
    CACHE STRING "" FORCE
)

################################################################################
# Global compiler options
################################################################################
if(MSVC)
    # remove default flags provided with CMake for MSVC
    set(CMAKE_CXX_FLAGS "")
    set(CMAKE_CXX_FLAGS_DEBUG "")
    set(CMAKE_CXX_FLAGS_RELEASE "")
endif()

################################################################################
# Global linker options
################################################################################
if(MSVC)
    # remove default flags provided with CMake for MSVC
    set(CMAKE_EXE_LINKER_FLAGS "")
    set(CMAKE_MODULE_LINKER_FLAGS "")
    set(CMAKE_SHARED_LINKER_FLAGS "")
    set(CMAKE_STATIC_LINKER_FLAGS "")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS}")
    set(CMAKE_MODULE_LINKER_FLAGS_DEBUG "${CMAKE_MODULE_LINKER_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS}")
    set(CMAKE_STATIC_LINKER_FLAGS_DEBUG "${CMAKE_STATIC_LINKER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS}")
    set(CMAKE_MODULE_LINKER_FLAGS_RELEASE "${CMAKE_MODULE_LINKER_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS}")
    set(CMAKE_STATIC_LINKER_FLAGS_RELEASE "${CMAKE_STATIC_LINKER_FLAGS}")
endif()

################################################################################
# Nuget packages function stub.
################################################################################
function(use_package TARGET PACKAGE VERSION)
    message(WARNING "No implementation of use_package. Create yours. "
                    "Package \"${PACKAGE}\" with version \"${VERSION}\" "
                    "for target \"${TARGET}\" is ignored!")
endfunction()

################################################################################
# Common utils
################################################################################
include(CMake/Utils.cmake)

################################################################################
# Additional Global Settings(add specific info there)
################################################################################
include(CMake/GlobalSettingsInclude.cmake OPTIONAL)

################################################################################
# Use solution folders feature
################################################################################
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

################################################################################
# Sub-projects
################################################################################



























set(PROJECT_NAME lifter)

################################################################################
# Source groups
################################################################################
set(Header_Files
    "CustomPasses.h"
    "includes.h"
    "LLVM-init.h"
    "nacibaba_opts.h"
    "OperandUtils.h"
    "ROPdetection.h"
    "Semantics.h"
    "utils.h"
)
source_group("Header Files" FILES ${Header_Files})

set(Source_Files
    "CustomPasses.cpp"
    "lifter.cpp"
    "LLVM-init.cpp"
    "nacibaba_opts.cpp"
    "OperandUtils.cpp"
    "ROPdetection.cpp"
    "Semantics.cpp"
    "utils.cpp"
)
source_group("Source Files" FILES ${Source_Files})

set(ALL_FILES
    ${Header_Files}
    ${Source_Files}
)

################################################################################
# Target
################################################################################
add_executable(${PROJECT_NAME} ${ALL_FILES})

# Set C++ standard to C++20
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS OFF
)

use_props(${PROJECT_NAME} "${CMAKE_CONFIGURATION_TYPES}" "${DEFAULT_CXX_PROPS}")
set_target_properties(${PROJECT_NAME} PROPERTIES
    VS_GLOBAL_KEYWORD "Win32Proj"
)
################################################################################
# Target name
################################################################################
set_target_properties(${PROJECT_NAME} PROPERTIES
    TARGET_NAME_DEBUG   "lifter"
    TARGET_NAME_RELEASE "lifter"
)
################################################################################
# Output directory
################################################################################
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_DIRECTORY_DEBUG   "${CMAKE_CURRENT_SOURCE_DIR}/x64/Debug/"
    OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/x64/Release/"
)
set_target_properties(${PROJECT_NAME} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY_DEBUG   "C:/Users/yusuf/Desktop/Z2LLVM/lifter/x64/Debug"
    ARCHIVE_OUTPUT_DIRECTORY_RELEASE "C:/Users/yusuf/Desktop/Z2LLVM/lifter/x64/Release"
)
set_target_properties(${PROJECT_NAME} PROPERTIES
    ARCHIVE_OUTPUT_NAME_DEBUG   "lifter"
    ARCHIVE_OUTPUT_NAME_RELEASE "lifter"
)
set_target_properties(${PROJECT_NAME} PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION_RELEASE "TRUE"
)
################################################################################
# MSVC runtime library
################################################################################
get_property(MSVC_RUNTIME_LIBRARY_DEFAULT TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY)
string(CONCAT "MSVC_RUNTIME_LIBRARY_STR"
    $<$<CONFIG:Debug>:
        MultiThreadedDebugDLL
    >
    $<$<CONFIG:Release>:
        MultiThreadedDLL
    >
    $<$<NOT:$<OR:$<CONFIG:Debug>,$<CONFIG:Release>>>:${MSVC_RUNTIME_LIBRARY_DEFAULT}>
)
set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY ${MSVC_RUNTIME_LIBRARY_STR})

################################################################################
# Include directories
################################################################################
target_include_directories(${PROJECT_NAME} PUBLIC
    "$<$<CONFIG:Debug>:"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../zydis-4.0.0/include;"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../zydis-4.0.0/dependencies/zycore/include;"
        "${CMAKE_CURRENT_SOURCE_DIR}/."
    ">"
    "$<$<CONFIG:Release>:"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../zydis/include;"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../zydis/dependencies/zycore/include"
    ">"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../llvm-project/llvm/include;"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../llvm-project/llvm/build/include"
)

################################################################################
# Compile definitions
################################################################################
target_compile_definitions(${PROJECT_NAME} PRIVATE
    "$<$<CONFIG:Debug>:"
        "_DEBUG;"
        "UNICODE;"
        "_UNICODE;"
        "CMAKE_INTDIR=\"Debug\";"
        "UNICODE;"
        "_UNICODE"
    ">"
    "$<$<CONFIG:Release>:"
        "NDEBUG;"
        "_MBCS;"
        "CMAKE_INTDIR=\"Release\";"
        "_MBCS"
    ">"
    "_CONSOLE"
)

################################################################################
# Compile and link options
################################################################################
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:
            /MP;
            /O2;
            /Ob2;
            /GF;
            /GT;
            /Oy;
            /Gy;
            /Ot;
            /fp:fast;
            /Oi-
        >
        /permissive-;
        /sdl;
        /arch:AVX2;
        /W3;
        /Zi;
        ${DEFAULT_CXX_EXCEPTION_HANDLING};
        /Y-
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Debug>:
            /INCREMENTAL
        >
        $<$<CONFIG:Release>:
            /OPT:REF;
            /OPT:ICF;
            /PROFILE
        >
        /MANIFEST;
        /DEBUG;
        /SUBSYSTEM:CONSOLE
    )
endif()

################################################################################
# Dependencies
################################################################################
set(ADDITIONAL_LIBRARY_DEPENDENCIES
    "$<$<CONFIG:Debug>:"
        "../../zydis-4.0.0/build/Debug/Zydis;"
        "../../zydis-4.0.0/build/zycore/Debug/Zycore;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMCore;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMExecutionEngine;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMC;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMCJIT;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSupport;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMX86CodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMX86Desc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMX86Info;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMOrcTargetProcess;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMOrcShared;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMRuntimeDyld;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMCDisassembler;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAsmPrinter;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMCFGuard;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMGlobalISel;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMInstrumentation;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSelectionDAG;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMTarget;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMBitWriter;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMObjCARCOpts;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMScalarOpts;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAggressiveInstCombine;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMInstCombine;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMCodeGenTypes;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMTransformUtils;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAnalysis;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMProfileData;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSymbolize;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMDebugInfoDWARF;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMDebugInfoPDB;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMObject;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMIRReader;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMBitReader;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMRemarks;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMBitstreamReader;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMCParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMTextAPI;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMBinaryFormat;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMTargetParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMDebugInfoCodeView;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMDebugInfoMSF;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMDebugInfoBTF;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMDemangle;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMPasses;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAArch64AsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAMDGPUAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMARMAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAVRAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMBPFAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMHexagonAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMLanaiAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMLoongArchAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMipsAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMSP430AsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMPowerPCAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMRISCVAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSparcAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSystemZAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMVEAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMWebAssemblyAsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMX86AsmParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAArch64CodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAMDGPUCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMARMCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAVRCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMBPFCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMHexagonCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMLanaiCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMLoongArchCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMipsCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMSP430CodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMNVPTXCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMPowerPCCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMRISCVCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSparcCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSystemZCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMVECodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMWebAssemblyCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMXCoreCodeGen;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAArch64Desc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAMDGPUDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMARMDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAVRDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMBPFDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMHexagonDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMLanaiDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMLoongArchDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMipsDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMSP430Desc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMNVPTXDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMPowerPCDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMRISCVDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSparcDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSystemZDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMVEDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMWebAssemblyDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMXCoreDesc;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAArch64Info;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAMDGPUInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMARMInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAVRInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMBPFInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMHexagonInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMLanaiInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMLoongArchInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMipsInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMSP430Info;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMNVPTXInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMPowerPCInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMRISCVInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSparcInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMSystemZInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMVEInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMWebAssemblyInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMXCoreInfo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMCoroutines;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMExtensions;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMipo;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMIRPrinter;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMVectorize;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAArch64Utils;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMAMDGPUUtils;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMMIRParser;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMARMUtils;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMFrontendOpenMP;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMLinker;"
        "../../llvm-project/llvm/build/Debug/lib/LLVMWebAssemblyUtils"
    ">"
    "$<$<CONFIG:Release>:"
        "../../zydis/ReleaseX64/Zydis;"
        "../../zydis/ReleaseX64/Zycore;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAArch64AsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAMDGPUAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMARMAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAVRAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMBPFAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMHexagonAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMLanaiAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMLoongArchAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMipsAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMSP430AsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMPowerPCAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMRISCVAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSparcAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSystemZAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMVEAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMWebAssemblyAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMX86AsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAArch64CodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAMDGPUCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMARMCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAVRCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMBPFCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMHexagonCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMLanaiCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMLoongArchCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMipsCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMSP430CodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMNVPTXCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMPowerPCCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMRISCVCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSparcCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSystemZCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMVECodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMWebAssemblyCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMX86CodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMXCoreCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAArch64Desc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAMDGPUDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMARMDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAVRDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMBPFDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMHexagonDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMLanaiDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMLoongArchDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMipsDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMSP430Desc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMNVPTXDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMPowerPCDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMRISCVDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSparcDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSystemZDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMVEDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMWebAssemblyDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMX86Desc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMXCoreDesc;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAArch64Info;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAMDGPUInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMARMInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAVRInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMBPFInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMHexagonInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMLanaiInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMLoongArchInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMipsInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMSP430Info;"
        "../../llvm-project/llvm/build/Release/lib/LLVMNVPTXInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMPowerPCInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMRISCVInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSparcInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSystemZInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMVEInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMWebAssemblyInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMX86Info;"
        "../../llvm-project/llvm/build/Release/lib/LLVMXCoreInfo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAggressiveInstCombine;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAnalysis;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAsmParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMBitWriter;"
        "../../llvm-project/llvm/build/Release/lib/LLVMCFGuard;"
        "../../llvm-project/llvm/build/Release/lib/LLVMCodeGen;"
        "../../llvm-project/llvm/build/Release/lib/LLVMCore;"
        "../../llvm-project/llvm/build/Release/lib/LLVMCoroutines;"
        "../../llvm-project/llvm/build/Release/lib/LLVMExtensions;"
        "../../llvm-project/llvm/build/Release/lib/LLVMipo;"
        "../../llvm-project/llvm/build/Release/lib/LLVMIRReader;"
        "../../llvm-project/llvm/build/Release/lib/LLVMIRPrinter;"
        "../../llvm-project/llvm/build/Release/lib/LLVMInstCombine;"
        "../../llvm-project/llvm/build/Release/lib/LLVMInstrumentation;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMC;"
        "../../llvm-project/llvm/build/Release/lib/LLVMObjCARCOpts;"
        "../../llvm-project/llvm/build/Release/lib/LLVMRemarks;"
        "../../llvm-project/llvm/build/Release/lib/LLVMScalarOpts;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSupport;"
        "../../llvm-project/llvm/build/Release/lib/LLVMTarget;"
        "../../llvm-project/llvm/build/Release/lib/LLVMTargetParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMTransformUtils;"
        "../../llvm-project/llvm/build/Release/lib/LLVMVectorize;"
        "../../llvm-project/llvm/build/Release/lib/LLVMPasses;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAArch64Utils;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAMDGPUUtils;"
        "../../llvm-project/llvm/build/Release/lib/LLVMHipStdPar;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMIRParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMARMUtils;"
        "../../llvm-project/llvm/build/Release/lib/LLVMFrontendOpenMP;"
        "../../llvm-project/llvm/build/Release/lib/LLVMFrontendOffloading;"
        "../../llvm-project/llvm/build/Release/lib/LLVMLinker;"
        "../../llvm-project/llvm/build/Release/lib/LLVMWebAssemblyUtils;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMCDisassembler;"
        "../../llvm-project/llvm/build/Release/lib/LLVMGlobalISel;"
        "../../llvm-project/llvm/build/Release/lib/LLVMAsmPrinter;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSelectionDAG;"
        "../../llvm-project/llvm/build/Release/lib/LLVMProfileData;"
        "../../llvm-project/llvm/build/Release/lib/LLVMSymbolize;"
        "../../llvm-project/llvm/build/Release/lib/LLVMDebugInfoDWARF;"
        "../../llvm-project/llvm/build/Release/lib/LLVMDebugInfoPDB;"
        "../../llvm-project/llvm/build/Release/lib/LLVMDebugInfoMSF;"
        "../../llvm-project/llvm/build/Release/lib/LLVMDebugInfoBTF;"
        "../../llvm-project/llvm/build/Release/lib/LLVMObject;"
        "../../llvm-project/llvm/build/Release/lib/LLVMMCParser;"
        "../../llvm-project/llvm/build/Release/lib/LLVMDebugInfoCodeView;"
        "../../llvm-project/llvm/build/Release/lib/LLVMBitReader;"
        "../../llvm-project/llvm/build/Release/lib/LLVMTextAPI;"
        "../../llvm-project/llvm/build/Release/lib/LLVMBitstreamReader;"
        "../../llvm-project/llvm/build/Release/lib/LLVMBinaryFormat;"
        "../../llvm-project/llvm/build/Release/lib/LLVMCodeGenTypes;"
        "../../llvm-project/llvm/build/Release/lib/LLVMDemangle;"
        "ws2_32"
    ">"
    "psapi;"
    "shell32;"
    "ole32;"
    "uuid;"
    "advapi32;"
    "delayimp;"
    "-delayload:shell32.dll;"
    "-delayload:ole32.dll;"
    "kernel32;"
    "user32;"
    "gdi32;"
    "winspool;"
    "oleaut32;"
    "comdlg32"
)
target_link_libraries(${PROJECT_NAME} PRIVATE "${ADDITIONAL_LIBRARY_DEPENDENCIES}")

