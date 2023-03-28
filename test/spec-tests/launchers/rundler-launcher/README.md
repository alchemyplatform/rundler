# Docker test environment

This docker-compose brings up a rundler, along with its supporting node (Geth).

**Usage:**

`rundler-launcher.sh start`
   - Start the bundler (and node) in the background.
   - Deploy the entrypoint contract.

`rundler-launcher.sh stop`
   - Stop runnning docker images.


**Can be used to launch tests (from bundler-spec-test) using:**

```
pdm run test --launcher-script=path/rundler-launcher.sh
```