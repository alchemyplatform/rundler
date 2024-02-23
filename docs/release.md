# Releases

The rundler project's releases are seamlessly managed by GitHub Actions and can be accessed here. This comprehensive workflow orchestrates multiple steps to compile and release new versions of the rundler project.

## Workflow Steps

# Extract Version

This initial step conditionally extracts the project version either from GitHub Actions inputs or the Git reference.

# Build

The build process is orchestrated to cater to various architectures and platforms. Using a dynamic matrix strategy, it defines distinct build configurations encompassing architecture, platform, and profile. Key actions include:

- Checking out the source code.
- Updating the Rust toolchain.
- Installing the target architecture.
- Leveraging the `Swatinem/rust-cache` action to efficiently cache Rust dependencies.
- Setting up essential environment variables for Apple Silicon SDK during Apple builds.
- Compiling the project with the specified profile and architecture.
- Organizing the compiled binary into a designated 'artifacts' directory.
- Adapting Windows builds by appending a '.exe' extension to the binary.

# Signing

Ensuring the integrity of the release, this step imports the GPG signing key and passphrase securely from GitHub secrets. It then generates GPG signatures for the resulting tarballs, strategically placing them in the root directory.

# Upload Artifacts

Leveraging the `actions/upload-artifact` action, this step uploads compressed artifacts along with their corresponding signatures to GitHub Actions.

# Draft Release

Dependent on the successful completion of the 'build' and 'extract-version' steps, this final step seamlessly manages the release draft. Actions include:

- Checking out the source code for the release process.
- Downloading the artifacts necessary for the release.
- Constructing a detailed changelog by extracting commit messages between the current and previous versions.
- Initiating the creation of a draft release on GitHub. The release template includes the changelog and convenient download links for the signed tarballs.
