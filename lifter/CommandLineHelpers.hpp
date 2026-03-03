#pragma once

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

inline void printLifterUsage(const char* executableName) {
  std::cerr << "Usage: " << executableName << " <filename> <startAddr>"
            << std::endl;
}

inline bool parseStartAddressArg(const std::string& rawStartAddress,
                                 uint64_t& outStartAddress) {
  try {
    size_t parsedLength = 0;
    outStartAddress = stoull(rawStartAddress, &parsedLength, 0);
    return parsedLength == rawStartAddress.size();
  } catch (const std::exception& ex) {
    std::cerr << "Failed to parse start address '" << rawStartAddress
              << "': " << ex.what() << std::endl;
    return false;
  }
}

inline bool readBinaryFile(const std::string& filename,
                           std::vector<uint8_t>& outFileData) {
  std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
  if (!ifs.is_open()) {
    std::cerr << "Failed to open file: " << filename << std::endl;
    return false;
  }

  const std::streamsize fileSize = ifs.tellg();
  if (fileSize <= 0) {
    std::cerr << "Input file is empty or unreadable: " << filename << std::endl;
    return false;
  }

  outFileData.resize(static_cast<size_t>(fileSize));
  ifs.seekg(0, std::ios::beg);
  if (!ifs.read(reinterpret_cast<char*>(outFileData.data()), fileSize)) {
    std::cerr << "Failed to read file bytes: " << filename << std::endl;
    return false;
  }

  return true;
}
