# Docker

To build Mergen in Docker run the following commands:

## Build image

```bash
docker build . -t mergen
```

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

