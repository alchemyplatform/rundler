# Docker test environment

This docker-compose brings up a alchemy-bundler, along with its supporting node (Geth).

**Usage:**

`alchemy-bundler-launcher.sh start`
   - Start the bundler (and node) in the background.
   - Deploy the entrypoint contract.

`alchemy-bundler-launcher.sh stop`
   - Stop runnning docker images.


**Can be used to launch tests (from bundler-spec-test) using:**

```
pdm run test --launcher-script=path/alchemy-bundler-launcher.sh
```