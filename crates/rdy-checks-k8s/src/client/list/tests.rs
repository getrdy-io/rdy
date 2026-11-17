//! Tests of the production paging helper over a service that serves generated pages. The recorded cases
//! (three pages, one restart on 410, the second 410 as the error) run against the M1-105 mock in
//! `client/mock/tests.rs`, which calls this same function.

use std::future::{Ready, ready};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use http::{Request, Response};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::client::Body;
use tower_service::Service;

use super::*;

/// Serves `pages` pages of `per_page` config maps. Every page but the last has a `continue` token. The
/// queries it was sent are kept.
#[derive(Clone)]
struct Pages {
    pages: usize,
    per_page: usize,
    queries: Arc<Mutex<Vec<String>>>,
    served: Arc<AtomicUsize>,
}

impl Pages {
    fn new(pages: usize, per_page: usize) -> Self {
        Self {
            pages,
            per_page,
            queries: Arc::default(),
            served: Arc::default(),
        }
    }
}

impl Service<Request<Body>> for Pages {
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Ready<Result<Response<Body>, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let query = request.uri().query().unwrap_or("").to_owned();
        self.queries.lock().expect("queries").push(query.clone());
        let page = self.served.fetch_add(1, Ordering::SeqCst);
        let items: Vec<String> = (0..self.per_page)
            .map(|n| format!(r#"{{"metadata":{{"name":"cm-{page}-{n}"}}}}"#))
            .collect();
        let next = if page + 1 < self.pages {
            format!(r#","continue":"tok-{}""#, page + 1)
        } else {
            String::new()
        };
        let body = format!(
            r#"{{"apiVersion":"v1","kind":"ConfigMapList","metadata":{{"resourceVersion":"1"{next}}},"items":[{}]}}"#,
            items.join(",")
        );
        ready(Ok(Response::new(Body::from(body.into_bytes()))))
    }
}

fn api(service: Pages) -> kube::Api<ConfigMap> {
    kube::Api::all(kube::Client::new(service, "default"))
}

#[tokio::test]
async fn a_list_is_read_in_pages_of_500_to_the_end() {
    let service = Pages::new(3, 500);
    let queries = Arc::clone(&service.queries);
    let listed = list_all(&api(service), &ListParams::default())
        .await
        .expect("three pages");
    assert_eq!(listed.items.len(), 1500);
    assert!(!listed.partial);
    assert_eq!(listed.restarts, 0);
    let queries = queries.lock().expect("queries").clone();
    assert_eq!(queries.len(), 3);
    assert!(queries.iter().all(|query| query.contains("limit=500")));
    assert!(queries[2].contains("continue=tok-2"), "{queries:?}");
}

#[tokio::test]
async fn the_cap_stops_the_walk_at_5000_objects_and_marks_the_answer_partial() {
    // 11 pages of 500 would be 5500 objects. The walk stops after the tenth page, and never asks for the
    // eleventh.
    let service = Pages::new(11, 500);
    let served = Arc::clone(&service.served);
    let listed = list_all(&api(service), &ListParams::default())
        .await
        .expect("a capped list");
    assert_eq!(listed.items.len(), MAX_ITEMS);
    assert!(listed.partial);
    assert_eq!(served.load(Ordering::SeqCst), 10);
}

#[tokio::test]
async fn a_list_of_exactly_the_cap_with_nothing_after_it_is_not_partial() {
    let listed = list_all(&api(Pages::new(10, 500)), &ListParams::default())
        .await
        .expect("ten pages");
    assert_eq!(listed.items.len(), MAX_ITEMS);
    assert!(!listed.partial);
}

#[tokio::test]
async fn a_page_that_runs_past_the_cap_is_cut_to_it() {
    // One page of 6000 objects, as a server that ignores the limit would send.
    let listed = list_all(&api(Pages::new(1, 6000)), &ListParams::default())
        .await
        .expect("one big page");
    assert_eq!(listed.items.len(), MAX_ITEMS);
    assert!(listed.partial);
}
