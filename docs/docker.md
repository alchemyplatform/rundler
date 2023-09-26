# Docker

## Build

To build the Docker container:

```
docker buildx build . -t rundler
```

## Run

Simple full node docker-compose configuration:

```
version: "3.8"

services:
  rundler:
    image: rundler
    ports:
      # RPC port
      - "3000:3000"
      # Metrics port
      - "8080:8080"
    environment:
      - ENTRY_POINTS=0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
      - NODE_HTTP=[YOUR NODE HTTP HERE]
      - CHAIN_ID=[YOUR CHAIN ID HERE]
      - BUILDER_PRIVATE_KEY=[YOUR PRIVATE KEY HERE]
```

An example docker-compose configuration running Rundler in its distributed mode can be found [here](../test/spec-tests/remote/docker-compose.yml). 
