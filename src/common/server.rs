pub fn format_server_addr(host: &String, port: u16) -> String {
    format!("{}:{}", host, port)
}
