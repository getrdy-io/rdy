//! The one way a check reads a whole list (03, "Paging").
//!
//! A list is read a page at a time (limit [`PAGE_LIMIT`]) by following the `continue` token. Two limits keep
//! a large cluster from costing a run:
//!
//! - **The cap.** At most [`MAX_ITEMS`] objects are kept. When the server has more, the walk stops and the
//!   answer is marked [`Listed::partial`], so the check says what it did not read.
//! - **One restart.** A `410 Gone` means the `continue` token expired. The walk starts over once from the
//!   first page. A second `410` is the error.
//!
//! Every page is a request through the guard, so each one is in the action log under the check's id.

use std::fmt;

use kube::api::ListParams;

/// The page size of every list.
pub(crate) const PAGE_LIMIT: u32 = 500;

/// The most objects one list keeps.
pub(crate) const MAX_ITEMS: usize = 5000;

/// A list read to the end, or to the cap.
#[derive(Debug)]
pub(crate) struct Listed<K> {
    /// The objects, in page order, at most [`MAX_ITEMS`].
    pub(crate) items: Vec<K>,
    /// How many times the walk started over after a `410 Gone`: 0 or 1.
    #[cfg_attr(not(test), expect(dead_code, reason = "only the paging tests read it"))]
    pub(crate) restarts: u32,
    /// The server had more than [`MAX_ITEMS`] objects, and the rest was not read.
    pub(crate) partial: bool,
}

/// Reads a whole list by following `continue` tokens, with the limits in the module text. `params`
/// carries the selectors; its limit is replaced by [`PAGE_LIMIT`].
///
/// # Errors
///
/// The `kube::Error` of the request that failed.
pub(crate) async fn list_all<K>(
    api: &kube::Api<K>,
    params: &ListParams,
) -> Result<Listed<K>, kube::Error>
where
    K: Clone + k8s_openapi::serde::de::DeserializeOwned + fmt::Debug,
{
    let params = params.clone().limit(PAGE_LIMIT);
    let mut restarts = 0;
    loop {
        let mut items: Vec<K> = Vec::new();
        let mut partial = false;
        let mut token: Option<String> = None;
        let walked: Result<(), kube::Error> = loop {
            let mut page = params.clone();
            if let Some(token) = &token {
                page = page.continue_token(token);
            }
            match api.list(&page).await {
                Ok(list) => {
                    items.extend(list.items);
                    let next = list.metadata.continue_.filter(|next| !next.is_empty());
                    if items.len() > MAX_ITEMS {
                        items.truncate(MAX_ITEMS);
                        partial = true;
                        break Ok(());
                    }
                    match next {
                        Some(_) if items.len() == MAX_ITEMS => {
                            partial = true;
                            break Ok(());
                        }
                        Some(next) => token = Some(next),
                        None => break Ok(()),
                    }
                }
                Err(error) => break Err(error),
            }
        };
        match walked {
            Ok(()) => {
                return Ok(Listed {
                    items,
                    restarts,
                    partial,
                });
            }
            Err(kube::Error::Api(status)) if status.code == 410 && restarts == 0 => restarts += 1,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests;
