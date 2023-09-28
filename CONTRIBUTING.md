## Contributing to Rundler

Thanks for your interest in improving Rundler!

There are multiple opportunities to contribute at any level. It doesn't matter if you are just getting started with Rust or are an expert, we can use your help.

**No contribution is too small and all contributions are valued.**

This document will help you get started. **Do not let the document intimidate you**.
It should be considered as a guide to help you navigate the process.

The [Telegram][dev-tg] is available for any concerns you may have that are not covered in this guide.

If you contribute to this project, your contributions will be made to the project as follows: (a) contributions to the Rundler library (i.e. all code outside of the `bin` directory) will be licensed under the GNU Lesser General Public License v3.0, also included in our repository in the COPYING.LESSER file; and (b) contributions to the Rundler binaries (i.e. all code inside of the `bin` directory) will be licensed under the GNU General Public License v3.0, also included in our repository in the COPYING file.

### Ways to contribute

There are fundamentally three ways an individual can contribute:

1. **By opening an issue:** For example, if you believe that you have uncovered a bug
   in Rundler, creating a new issue in the [issue tracker][gh-issues] is the way to report it.
2. **By adding context:** Providing additional context to existing issues,
   such as screenshots and code snippets to help resolve issues.
3. **By resolving issues:** Typically this is done in the form of either
   demonstrating that the issue reported is not a problem after all, or more often,
   by opening a pull request that fixes the underlying problem, in a concrete and
   reviewable manner.

**Anybody can participate in any stage of contribution**. We urge you to participate in the discussion around bugs and participate in reviewing PRs.

### Submitting a bug report

When filing a new bug report in the [issue tracker][gh-issues], you will be presented with a basic form to fill out.

If you believe that you have uncovered a bug, please fill out the form to the best of your ability. Do not worry if you cannot answer every detail, just fill in what you can. Contributors will ask follow-up questions if something is unclear.

The most important pieces of information we need in a bug report are:

-   The Rundler version you are on (and that it is up to date)
-   The platform you are on (Windows, macOS, an M1 Mac or Linux)
-   Code snippets if this is happening in relation to testing or building code
-   Concrete steps to reproduce the bug

In order to rule out the possibility of the bug being in your project, the code snippets should be as minimal as possible. It is better if you can reproduce the bug with a small snippet as opposed to an entire project!

### Submitting a feature request

When adding a feature request in the issue tracker, you will be presented with a basic form to fill out.

Please include as detailed of an explanation as possible of the feature you would like, adding additional context if necessary.

If you have examples of other tools that have the feature you are requesting, please include them as well.

### Resolving an issue

Pull requests are the way concrete changes are made to the code, documentation, and dependencies of Rundler.

Even tiny pull requests, like fixing wording, are greatly appreciated. Before making a large change, it is usually a good idea to first open an issue describing the change to solicit feedback and guidance. This will increase the likelihood of the PR getting merged.

Please also make sure that the following commands pass if you have changed the code:

```sh
cargo check --all
cargo test --all --all-features
cargo +nightly fmt -- --check
cargo +nightly clippy --all --all-features -- -D warnings
```

If you are working in VSCOde, we recommend you install the [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer) extension, and use the following VSCode user settings:
```
    "[rust]": {
        "editor.defaultFormatter": "rust-lang.rust-analyzer",
        "editor.formatOnSave": true
    },
    "rust-analyzer.rustfmt.extraArgs": [
        "+nightly"
    ],
    "rust-analyzer.check.command": "clippy",
    "rust-analyzer.files.excludeDirs": [
      "crates/sim/contracts",
      "crates/sim/tracer",
      "crates/builder/proto",
      "crates/pool/proto",
      "test",
    ],
```

If you are working on a larger feature, we encourage you to open up a draft pull request, to make sure that other contributors are not duplicating work.

#### Adding tests

If the change being proposed alters code, it is either adding new functionality to Rundler, or fixing existing, broken functionality.
In both of these cases, the pull request should include one or more tests to ensure that Rundler does not regress in the future.

#### Commits

It is a recommended best practice to keep your changes as logically grouped as possible within individual commits. There is no limit to the number of commits any single pull request may have, and many contributors find it easier to review changes that are split across multiple commits.
That said, if you have a number of commits that are "checkpoints" and don't represent a single logical change, please squash those together.

We follow the [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) specification to make sure that all of our commits are formatted and properly tailored to the change that the commit is making. Please choose commit messages that correctly describe the change you are making.

#### Opening the pull request

From within GitHub, opening a new pull request will present you with a template that should be filled out. Please try your best at filling out the details, but feel free to skip parts if you're not sure what to put.

*Adapted from the [Reth contributing guide](https://github.com/paradigmxyz/reth/blob/main/CONTRIBUTING.md).*

[dev-tg]: https://t.me/rundler
[gh-issues]: https://github.com/alchemyplatform/rundler/issues/new/choose
