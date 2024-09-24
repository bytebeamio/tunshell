use reqwest;
use std::collections::HashMap;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::time::sleep;
use tunshell_client as client;
use tunshell_server as server;

#[test]
fn test() {
    Runtime::new().unwrap().block_on(async {
        let mut config = server::relay::Config::from_env().unwrap();
        config.tls_port = 20003;
        config.api_port = 20004;

        tokio::task::spawn(server::start(config.clone()));

        sleep(Duration::from_millis(1000)).await;

        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let response = http
            .post(format!("https://localhost:{}/api/sessions", config.api_port).as_str())
            .send()
            .await
            .unwrap()
            .json::<HashMap<String, String>>()
            .await
            .unwrap();

        let target_key = response.get("peer1_key").unwrap();
        let client_key = response.get("peer2_key").unwrap();

        let target_shell = client::HostShell::new().unwrap();

        let mut target_config = client::Config::new(
            client::ClientMode::Target,
            target_key,
            "localhost.tunshell.com",
            config.tls_port,
            config.api_port,
            "mock_encryption_key",
            true,
            false,
        );
        target_config.set_dangerous_disable_relay_server_verification(true);
        let mut target = client::Client::new(target_config, target_shell.clone());

        let local_shell = client::HostShell::new().unwrap();

        let mut local_config = client::Config::new(
            client::ClientMode::Local,
            client_key,
            "localhost.tunshell.com",
            config.tls_port,
            config.api_port,
            "mock_encryption_key",
            true,
            false,
        );
        local_config.set_dangerous_disable_relay_server_verification(true);
        let mut local = client::Client::new(local_config, local_shell.clone());

        let session_task = tokio::spawn(async move {
            futures::future::join(local.start_session(), target.start_session()).await
        });

        local_shell.write_to_stdin("echo hello\n".as_bytes());
        local_shell.write_to_stdin("exit\n".as_bytes());

        let result = session_task.await.unwrap();
        assert_eq!((result.0.unwrap(), result.1.unwrap()), (0, 0));
    })
}
