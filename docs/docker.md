# Docker

## Build

To build the Docker container:

```
docker buildx build . -t rundler
```

## Run

Sample full node docker-compose configuration:

```
services:
  rundler:
    image: rundler
    command: node
    ports:
      # RPC port
      - "3000:3000"
      # Metrics port
      - "8080:8080"
    environment:
      - RUST_LOG=INFO
      - NETWORK=[YOUR NETWORK HERE]
      - NODE_HTTP=[YOUR NODE HTTP HERE]
      - BUILDER_PRIVATE_KEY=[YOUR PRIVATE KEY HERE]
      - DISABLE_ENTRY_POINT_V0_6=true
```

See [CLI docs](./cli.md) for more info on the environment variables.

An example docker-compose configuration running Rundler in its distributed mode can be found [here](../test/spec-tests/remote/docker-compose.yml). 

## Cross-Platform Docker Builds with Docker and cross-rs

### Prerequisites

- [cross-rs](https://github.com/cross-rs/cross)  
- [tonistiigi/binfmt](https://github.com/tonistiigi/binfmt)  
- [docker-buildx](https://github.com/docker/buildx)  

### Build Phase [Dockerfile.build](../Dockerfile.build)

This phase compiles and imports required libraries for successful compilation. It uses the Dockerfile.build as an environment. The base image is specified by the `CROSS_BASE_IMAGE` argument. A list of images that `cross-rs` provides can be found [here](https://github.com/cross-rs/cross/tree/main/docker).

### Release Phase [Dockerfile.cross](../Dockerfile.cross)

This phase imports the compiled binary from the previous stage into its environment and exposes relevant ports for the correct functioning of the program. The target platform is specified by the `TARGETPLATFORM` argument.

### Usage

**GitHub Actions**

```
jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - name: Set up Docker builder
        run: |
          docker run --privileged --rm tonistiigi/binfmt --install arm64,amd64
          docker buildx create --use --name cross-builder

      - name: Build and push image
        run: |
          cargo install cross --git https://github.com/cross-rs/cross 
          sudo -E env "PATH=$PATH" make docker-build-latest
```

**Local Builds**

These command should only be used if you are trying to cross compile the application locally. If you just want to build cross compiled docker images, you should use the commands above.


```
docker run --privileged --rm tonistiigi/binfmt --install arm64,amd64
docker buildx create --use --name cross-builder
cargo install cross --git https://github.com/cross-rs/cross 
sudo -E env "PATH=$PATH" make docker-build-latest
```
