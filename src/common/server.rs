pub fn format_server_addr(host: &String, port: u16, secure: bool) -> String {
    if secure {
        format!("https://{}:{}", host, port)
    } else {
        format!("http://{}:{}", host, port)
    }
}

pub fn format_socket_addr(host: &String, port: u16) -> String {
    format!("{}:{}", host, port)
}
