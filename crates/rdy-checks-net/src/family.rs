//! The `net` family: the checks of `rdy-checks-net` that are built, and the hosts each may reach.

use rdy_engine::check::CheckInfo;
use rdy_engine::family::{BuildError, Built, Family, HostSet};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};

use crate::egress::{self, EgressCheck};

/// Every `net.*` check this crate has built, in catalog order. `net.proxy`, `net.tls_intercept` and the
/// M1-late checks are not here, so the planner skips them as `not_in_build`.
static CHECKS: [&CheckInfo; 1] = [&egress::INFO];

/// The `net` family. It builds `net.egress`.
///
/// A check gets the hosts its own spec entry lists and no others (INV-11): for `net.egress`, its
/// `endpoints`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetFamily;

impl Family for NetFamily {
    fn name(&self) -> &'static str {
        "net"
    }

    fn checks(&self) -> &'static [&'static CheckInfo] {
        &CHECKS
    }

    fn build(&self, _: &CheckSpec, params: CheckParams, _: &Spec) -> Result<Built, BuildError> {
        match params {
            CheckParams::NetEgress(params) => {
                let hosts = HostSet::new(params.endpoints.iter().map(|e| e.target.clone()));
                Ok(Built::new(Box::new(EgressCheck::new(params))).with_hosts(hosts))
            }
            _ => Err(BuildError::Unsupported(
                "this net check is not built yet".to_owned(),
            )),
        }
    }
}
