use metrics::Counter;

pub struct OpPoolMetrics {
    pub request_counter: Counter,
}

impl Default for OpPoolMetrics {
    fn default() -> Self {
        Self {
            request_counter: metrics::register_counter!("op_pool_num_requests"),
        }
    }
}
