use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::Result;

pub struct DummyConnection;

impl DummyConnection {
    pub async fn health_check(&self) -> Result<()> {
        // Simulate a lightweight query like SELECT 1
        // tokio::time::sleep(std::time::Duration::from_micros(10)).await;
        Ok(())
    }
    
    pub async fn reset(&self) {
        // Simulate connection reset
    }
}

pub struct SafeConnectionPool {
    connections: Arc<Mutex<Vec<DummyConnection>>>,
}

impl SafeConnectionPool {
    pub fn new(size: usize) -> Self {
        let mut conns = Vec::with_capacity(size);
        for _ in 0..size {
            conns.push(DummyConnection);
        }
        Self {
            connections: Arc::new(Mutex::new(conns)),
        }
    }

    pub async fn acquire(&self) -> Option<DummyConnection> {
        let mut pool = self.connections.lock().await;
        if let Some(conn) = pool.pop() {
            if conn.health_check().await.is_ok() {
                return Some(conn);
            }
        }
        None
    }

    pub async fn release(&self, conn: DummyConnection) {
        conn.reset().await;
        let mut pool = self.connections.lock().await;
        pool.push(conn);
    }
}
