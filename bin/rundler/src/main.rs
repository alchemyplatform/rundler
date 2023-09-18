use dotenv::dotenv;
mod cli;

#[tokio::main]
async fn main() {
    dotenv().ok();
    if let Err(err) = cli::run().await {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
