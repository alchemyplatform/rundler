use crate::common::protos::op_pool::op_pool_client::OpPoolClient;
use crate::common::types::UserOperation;
use ethers::types::{Bytes, OpCode};
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Represents types whose `Clone` implementation does not allocate. Allows
/// calling `.cheap_clone()` instead of `.clone()`, which does the same thing
/// but is visually clear that the operation is not expensive, and makes it
/// impossible to accidentally switch to an expensive clone during refactors.
pub trait CheapClone: Clone {
    fn cheap_clone(&self) -> Self {
        self.clone()
    }
}

impl<T> CheapClone for Rc<T> {}

impl<T> CheapClone for Arc<T> {}

impl CheapClone for Bytes {}

impl<T> CheapClone for mpsc::Sender<T> {}

impl CheapClone for UserOperation {}

impl CheapClone for OpCode {}

// This one does actually allocate, but it's still an "intended" clone that's
// cheap for its purpose.
// See: https://docs.rs/tonic/latest/tonic/client/index.html#concurrent-usage
impl<T: Clone> CheapClone for OpPoolClient<T> {}
