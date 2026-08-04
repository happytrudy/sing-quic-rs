use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use tokio::sync::Notify;

#[derive(Clone, Default)]
pub(crate) struct TaskGroup {
    state: Arc<TaskState>,
}

#[derive(Default)]
struct TaskState {
    active: AtomicUsize,
    cancelled: AtomicBool,
    cancel_notify: Notify,
    done_notify: Notify,
}

impl TaskGroup {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.state.active.fetch_add(1, Ordering::AcqRel);
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let _guard = TaskGuard {
                state: Arc::clone(&state),
            };
            let cancelled = state.cancel_notify.notified();
            if state.cancelled.load(Ordering::Acquire) {
                return;
            }
            tokio::select! {
                _ = cancelled => {}
                _ = future => {}
            }
        });
    }

    pub(crate) async fn cancel_and_wait(&self) {
        self.state.cancelled.store(true, Ordering::Release);
        self.state.cancel_notify.notify_waiters();
        loop {
            let notified = self.state.done_notify.notified();
            if self.state.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct TaskGuard {
    state: Arc<TaskState>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::AcqRel);
        self.state.done_notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancellation_releases_blocked_task() {
        let tasks = TaskGroup::new();
        tasks.spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        tokio::time::timeout(Duration::from_secs(1), tasks.cancel_and_wait())
            .await
            .expect("task group cancellation timed out");
    }
}
