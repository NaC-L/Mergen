
**NOTE"": When cloning this repo, don't forget to add **--recursive** flag. 
So the command should look like this:

```bash
git clone --recursive https://github.com/NaC-L/Mergen
```

# Docker

To build Mergen in Docker run the following commands:

## Build image

```bash
docker build . -t mergen
```

## Run

```bash
docker run -it --rm mergen
```


## Building with Windows
If you have built llvm, this command should work.
```
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER="clang++" -DCMAKE_C_COMPILER="clang" -G "Ninja" -DLLVM_DIR="<path_to_llvm_dir>\build\lib\cmake\llvm" -DLLVM_INCLUDE_DIRS=<path_to_llvm_include_dirs> -DLLVM_LIBRARY_DIR=<path_to_llvm_library_dir>
```