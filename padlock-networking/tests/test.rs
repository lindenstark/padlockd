use std::error::Error;

use padlock_networking::*;

#[tokio::test]
async fn create_default_node() -> Result<(), Box<dyn Error>> {
    let _ = Node::create(Configuration::default());

    Ok(())
}

#[tokio::test]
async fn create_custom_node() -> Result<(), Box<dyn Error>> {
    let _ = Node::create(Configuration {
        port: 5555,

        node_timeout: 10000,
        wallet_timeout: 10000,

        max_node_size: 50,
        max_wallet_size: 500,

        max_node_connections: 1,
        max_wallet_connections: 100,
    });

    Ok(())
}

#[tokio::test]
async fn create_default_node_and_swap() -> Result<(), Box<dyn Error>> {
    let mut configuration = Configuration::default();
    let node = Node::create(Configuration::default());

    configuration.port = 5555;
    node.swap(configuration);

    Ok(())
}

#[tokio::test]
async fn run_default_node() -> Result<(), Box<dyn Error>> {
    let node = Node::create(Configuration::default());

    node.listen().await;

    Ok(())
}
