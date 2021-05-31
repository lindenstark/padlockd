extern crate futures;

extern crate h2;
use h2::{server, RecvStream, SendStream};

extern crate bytes;
use bytes::Bytes;

extern crate http;
use http::{Request, Response, StatusCode};

extern crate crossbeam;
use crossbeam::atomic::AtomicCell;

extern crate tokio;
use tokio::{
    net::{TcpListener, TcpStream},
    time::{sleep, Duration},
};

use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
pub struct Configuration {
    pub port: u16,

    pub node_timeout: u32,   //MS
    pub wallet_timeout: u32, //MS

    pub max_node_size: usize,   //KB
    pub max_wallet_size: usize, //KB

    pub max_node_connections: usize,
    pub max_wallet_connections: usize,
}

impl Default for Configuration {
    fn default() -> Configuration {
        Configuration {
            port: 4444,

            node_timeout: 300000,
            wallet_timeout: 300000,

            max_node_size: 15000,
            max_wallet_size: 1000,

            max_node_connections: 50,
            max_wallet_connections: 5000,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct State {
    pub configuration: Configuration,

    active: bool,

    node_connections: usize,
    wallet_connections: usize,
}

#[derive(Debug, Clone)]
pub struct Node {
    state: Arc<AtomicCell<State>>,
}

#[derive(Debug, Copy, Clone)]
enum Client {
    Wallet,
    Node,
}

impl Node {
    pub fn create(configuration: Configuration) -> Node {
        Node {
            state: Arc::new(AtomicCell::new(State {
                configuration: configuration,

                active: false,

                node_connections: 0,
                wallet_connections: 0,
            })),
        }
    }

    pub fn swap(&self, configuration: Configuration) {
        let mut state = self.state.load();

        state.configuration = configuration;

        self.state.swap(state);
    }

    pub async fn listen(self) {
        let mut state = self.state.load();

        state.active = true;

        self.state.swap(state);

        loop {
            let current_state = self.state.load();

            if current_state.active == true {
                host(Arc::clone(&self.state)).await;
            }

            sleep(Duration::from_millis(50)).await;
        }
    }
}

async fn host(state: Arc<AtomicCell<State>>) {
    let listener = TcpListener::bind(format!(
        "127.0.0.1:{}",
        state.load().configuration.port
    ))
    .await
    .unwrap();

    loop {
        if &state.load().active == &true {
            if let Ok((socket, _)) = listener.accept().await {
                let handle_state = state.clone();

                tokio::spawn(async move {
                    handle(socket, handle_state).await;
                });
            }
        } else {
            break;
        }
    }
}

async fn handle(socket: TcpStream, state: Arc<AtomicCell<State>>) {
    if let Ok(mut connection) = server::handshake(socket).await {
        let mut current_state = state.load();

        while let Some(result) = connection.accept().await {
            if let Ok((request, mut respond)) = result {
                let builder = Response::builder();

                let mut client: Option<Client> = None;
                let mut response: Option<Response<()>> = None;

                if request.headers().contains_key("client") {
                    match request
                        .headers()
                        .get("client")
                        .unwrap()
                        .to_str()
                        .unwrap()
                    {
                        "node" => {
                            if current_state.node_connections
                                != current_state
                                    .configuration
                                    .max_node_connections
                            {
                                response = Some(
                                    builder
                                        .status(StatusCode::OK)
                                        .body(())
                                        .unwrap(),
                                );

                                client = Some(Client::Node);

                                current_state.node_connections =
                                    current_state.node_connections + 1;
                            } else {
                                response = Some(
                                    builder
                                        .status(
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                        )
                                        .body(())
                                        .unwrap(),
                                );
                            }
                        }

                        "wallet" => {
                            if current_state.wallet_connections
                                != current_state
                                    .configuration
                                    .max_wallet_connections
                            {
                                response = Some(
                                    builder
                                        .status(StatusCode::OK)
                                        .body(())
                                        .unwrap(),
                                );

                                client = Some(Client::Wallet);

                                current_state.wallet_connections =
                                    current_state.wallet_connections + 1;
                            } else {
                                response = Some(
                                    builder
                                        .status(
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                        )
                                        .body(())
                                        .unwrap(),
                                );
                            }
                        }

                        _ => {
                            response = Some(
                                builder
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(())
                                    .unwrap(),
                            );
                        }
                    }
                } else {
                    response = Some(
                        builder
                            .status(StatusCode::BAD_REQUEST)
                            .body(())
                            .unwrap(),
                    );
                }

                if client.is_none() == true {
                    respond.send_response(response.unwrap(), true);
                } else {
                    state.swap(current_state);

                    if let Ok(mut stream) =
                        respond.send_response(response.unwrap(), false)
                    {
                        match client.unwrap() {
                            Client::Node => {
                                stream.reserve_capacity(
                                    current_state.configuration.max_node_size,
                                );
                            }

                            Client::Wallet => {
                                stream.reserve_capacity(
                                    current_state.configuration.max_wallet_size,
                                );
                            }
                        }

                        direct_stream(
                            &mut stream,
                            request,
                            client.unwrap(),
                            state.clone(),
                        )
                        .await;
                    }

                    match client.unwrap() {
                        Client::Node => {
                            current_state.node_connections =
                                current_state.node_connections - 1;
                        }

                        Client::Wallet => {
                            current_state.wallet_connections =
                                current_state.wallet_connections - 1;
                        }
                    }

                    state.swap(current_state);
                }
            }
        }
    }
}

async fn direct_stream(
    stream: &mut SendStream<Bytes>,
    request: Request<RecvStream>,
    client: Client,
    state: Arc<AtomicCell<State>>,
) {
    match request.uri().path() {
        "/ping" => {
            stream.send_data(Bytes::from("pong\n"), true).unwrap();
        }

        _ => {
            stream.send_data(Bytes::new(), true).unwrap();
        }
    }
}
