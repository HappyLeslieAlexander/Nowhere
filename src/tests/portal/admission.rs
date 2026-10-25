// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Test-only inspection of unauthenticated admission counters.

use super::*;

impl UnauthenticatedAdmission {
    pub(in crate::portal) fn active(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .total
    }
}

#[test]
fn unauthenticated_budgets_bound_sources_and_reclaim_permissions() {
    let admission = Arc::new(UnauthenticatedAdmission::new());
    let mut held = Vec::new();
    for _ in 0..MAX_UNAUTHENTICATED_PER_SOURCE {
        held.push(admission.try_acquire("127.0.0.1".parse().unwrap()).unwrap());
    }
    assert!(
        admission
            .try_acquire("127.0.0.1".parse().unwrap())
            .is_none()
    );
    held.pop();
    assert!(
        admission
            .try_acquire("127.0.0.1".parse().unwrap())
            .is_some()
    );
    drop(held);
    assert_eq!(admission.active(), 0);
    let mut held = Vec::new();
    for index in 0..MAX_UNAUTHENTICATED_CONNECTIONS {
        held.push(
            admission
                .try_acquire(IpAddr::V4(Ipv4Addr::new(
                    10,
                    0,
                    (index / 255) as u8,
                    index as u8,
                )))
                .unwrap(),
        );
    }
    assert!(
        admission
            .try_acquire("192.0.2.1".parse().unwrap())
            .is_none()
    );
    drop(held);
    assert_eq!(admission.active(), 0);
    let held = (0..MAX_UNAUTHENTICATED_PER_SOURCE)
        .map(|i| {
            admission
                .try_acquire(format!("2001:db8:1:2::{i:x}").parse().unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(
        admission
            .try_acquire("2001:db8:1:2::ffff".parse().unwrap())
            .is_none()
    );
    assert!(
        admission
            .try_acquire("2001:db8:1:3::1".parse().unwrap())
            .is_some()
    );
    drop(held);
    assert_eq!(admission.active(), 0);
}

#[tokio::test]
async fn waiters_wake_on_release_and_cancel_without_leaking_admission() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let admission = Arc::new(UnauthenticatedAdmission::new());
    let source = "127.0.0.1".parse().unwrap();
    let mut held = (0..MAX_UNAUTHENTICATED_PER_SOURCE)
        .map(|_| admission.try_acquire(source).unwrap())
        .collect::<Vec<_>>();
    let waiting = admission.acquire(source);
    tokio::pin!(waiting);
    poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    held.pop();
    let promoted = tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
        .await
        .unwrap();
    assert_eq!(admission.active(), MAX_UNAUTHENTICATED_PER_SOURCE);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..MAX_UNAUTHENTICATED_PER_SOURCE {
        let admission = admission.clone();
        tasks.spawn(async move { admission.acquire(source).await });
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), tasks.join_next())
            .await
            .is_err()
    );
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    assert_eq!(admission.active(), MAX_UNAUTHENTICATED_PER_SOURCE);
    drop(promoted);
    drop(held);
    assert_eq!(admission.active(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_release_and_cancellation_reclaim_every_processing_permit() {
    for _ in 0..64 {
        let admission = Arc::new(UnauthenticatedAdmission::new());
        let source = "127.0.0.1".parse().unwrap();
        let held = (0..MAX_UNAUTHENTICATED_PER_SOURCE)
            .map(|_| admission.try_acquire(source).unwrap())
            .collect::<Vec<_>>();
        let start = Arc::new(tokio::sync::Barrier::new(
            MAX_UNAUTHENTICATED_PER_SOURCE + 1,
        ));
        let tasks = (0..MAX_UNAUTHENTICATED_PER_SOURCE)
            .map(|_| {
                let admission = admission.clone();
                let start = start.clone();
                tokio::spawn(async move {
                    start.wait().await;
                    admission.acquire(source).await
                })
            })
            .collect::<Vec<_>>();
        start.wait().await;
        drop(held);
        for task in tasks.iter().step_by(2) {
            task.abort();
        }
        let mut promoted = Vec::new();
        for task in tasks {
            match tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .unwrap()
            {
                Ok(guard) => promoted.push(guard),
                Err(error) => assert!(error.is_cancelled()),
            }
        }
        assert!(promoted.len() >= MAX_UNAUTHENTICATED_PER_SOURCE / 2);
        assert_eq!(admission.active(), promoted.len());
        drop(promoted);
        assert_eq!(admission.active(), 0);
    }
}
