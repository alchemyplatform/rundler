use alchemy_bundler::cli;

#[tokio::main]
async fn main() {
    if let Err(err) = cli::run().await {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
