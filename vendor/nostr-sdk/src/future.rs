use std::pin::Pin;

pub(crate) type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
