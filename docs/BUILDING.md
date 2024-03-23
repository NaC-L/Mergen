
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
