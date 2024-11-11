# Docker

To build Mergen in Docker run the following commands:

## Build image

```bash
docker build . -t mergen
```
---

## Run

Place target binary in the Mergen's root dir, then run following command.

Note that you have to replace target.exe with your binary and 0x123456789 with your obfuscated function address.

```bash
# Powershell
docker run --rm -v ${PWD}:/data mergen target.exe 0x123456789

# command prompt
docker run --rm -v %cd%:/data mergen target.exe 0x123456789

# bash
docker run --rm -v $PWD:/data mergen target.exe 0x123456789
```
---

# Windows

Here's a detailed guide to setting up your environment to build LLVM 18.1.0 on Windows, using Clang and Ninja, and configuring it to compile Mergen.

---

# Building LLVM 18.1.0 from Scratch on Windows

To set up and build LLVM 18.1.0 from scratch on Windows, follow these steps. This guide includes instructions on installing the necessary tools, setting up Visual Studio and the correct SDK, configuring paths, and building with Ninja.

### Prerequisites

---

1. **Download and Install LLVM 18.1.0**
    - Download the LLVM 18.1.0 pre-built installer for Windows from this link: [LLVM-18.1.0-win64.exe](https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.0/LLVM-18.1.0-win64.exe).
    - Run the installer and follow the on-screen instructions.
    - During installation, choose the option to set the `PATH` environment variable for either:
        - **All users** or **Current user only**, depending on your preference.
    - This configuration will make `clang` and `clang++` directly accessible from any command prompt or terminal.

2. **Download LLVM Source**
    - Download LLVM 18.1.0 source from the [official release page](https://github.com/llvm/llvm-project/releases/tag/llvmorg-18.1.0).
    - Direct link to the source: [llvmorg-18.1.0.zip](https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-18.1.0.zip)
    - Extract the archive to a directory of your choice (e.g., `C:\llvm-project`).

3. **Install Visual Studio 2022**
    - Download and install **Visual Studio 2022** (Community edition is sufficient).
    - During installation, ensure you select:
        - **Desktop development with C++** workload.
        - Under Individual Components, check:
            - **MSVC v143 - VS 2022 C++ x64/x86 build tools**
            - **C++ CMake tools for Windows**
            - **Windows 10 SDK (10.0.19041.0)** or newer.
    - Make a note of the installation path, typically:
        - `C:\Program Files\Microsoft Visual Studio\2022\Community`

4. **Set Up System Environment Variables**
    - Open the Environment Variables settings in Windows and add the following paths to your `Path` variable:
        - **Ninja** (if not already installed):
            - Download Ninja from [Ninja GitHub](https://github.com/ninja-build/ninja/releases) and add the path to `ninja.exe` to your `Path`.
        - **CMake**:
            - If CMake is not installed, download it from [CMake's website](https://cmake.org/download/) and add it to your `Path`.
        - **LLVM tools** (once LLVM is built, add the installation directory to `Path` as needed).

5. **Additional Environment Variables for LLVM and Visual Studio Paths**
    - Define `CMAKE_C_COMPILER` and `CMAKE_CXX_COMPILER` paths to ensure LLVM uses the correct compiler:
        - `CMAKE_C_COMPILER="C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.41.34120/bin/Hostx64/x64/cl.exe"`
        - `CMAKE_CXX_COMPILER="C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.41.34120/bin/Hostx64/x64/cl.exe"`
    - Set the Windows Kit paths, specifically `RC` and `MT`:
        - `CMAKE_RC_COMPILER="C:/Program Files (x86)/Windows Kits/10/bin/10.0.19041.0/x64/rc.exe"`
        - `CMAKE_MT="C:/Program Files (x86)/Windows Kits/10/bin/10.0.19041.0/x64/mt.exe"`
    - Optionally, define `LLVM_INSTALL_PREFIX` for the installation directory:
        - Example: `LLVM_INSTALL_PREFIX="C:\llvm_stuff"`

### Building LLVM with Ninja

1. **Open a Developer Command Prompt**
    - Open a command prompt configured for Visual Studio:
        - Navigate to **Start Menu > Visual Studio 2022 > Developer Command Prompt for Visual Studio 2022**.

2. **Configure the Build with CMake**
    - Navigate to the root of the LLVM source directory:
      ```bash
      cd C:\llvm-project
      ```
    - Run CMake with the following configuration:
      ```bash
      cmake -G "Ninja" -S llvm -B build -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86" -DCMAKE_INSTALL_PREFIX="C:\llvm_stuff" -DLLVM_HOST_TRIPLE=x86_64-pc-windows-msvc -DCMAKE_C_COMPILER="C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.41.34120/bin/Hostx64/x64/cl.exe" -DCMAKE_CXX_COMPILER="C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.41.34120/bin/Hostx64/x64/cl.exe" -DCMAKE_RC_COMPILER="C:/Program Files (x86)/Windows Kits/10/bin/10.0.19041.0/x64/rc.exe" -DCMAKE_MT="C:/Program Files (x86)/Windows Kits/10/bin/10.0.19041.0/x64/mt.exe"
      ```

3**Install LLVM**
    - Once built, install LLVM to the specified installation directory:
      ```bash
      ninja -C build install
      ```

Here’s the updated **Setting Up Mergen Build** section with the repository URL included and configured for a recursive clone:

---

### Setting Up Mergen Build

With LLVM successfully built and installed, you can configure Mergen to use the newly built LLVM.

1. **Set the `LLVM_DIR` Environment Variable**
    - To ensure Mergen can locate the LLVM CMake configuration files, set `LLVM_DIR` as a system environment variable.
    - Open Command Prompt as Administrator and run the following command:
      ```cmd
      setx LLVM_DIR "c:\llvm_stuff\build\lib\cmake\llvm" /M
      ```
    - Alternatively, in PowerShell (also as Administrator), use:
      ```powershell
      [System.Environment]::SetEnvironmentVariable("LLVM_DIR", "C:\llvm_stuff\build\lib\cmake\llvm", "Machine")
      ```
    - This makes `LLVM_DIR` available system-wide, allowing CMake to locate LLVM when building Mergen. Restart any command prompt or terminal session to ensure the environment variable is recognized.

2. **Clone the Mergen Repository** (recursively, to include submodules):
   ```bash
   git clone --recursive https://github.com/NaC-L/Mergen.git
   cd Mergen
   ```

3. **Run CMake for Mergen Build**
    - Configure CMake to use Clang as the compiler:
      ```bash
      cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER="clang++" -DCMAKE_C_COMPILER="clang"
      ```

4. **Build Mergen with Ninja**
   ```bash
   ninja
   ```

---

