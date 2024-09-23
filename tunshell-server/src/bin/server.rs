use anyhow::Result;
use tunshell_server::relay;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    tunshell_server::start(relay::Config::from_env()?).await
}
