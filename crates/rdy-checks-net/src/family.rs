//! The net family: the checks that exist so far and how a spec entry builds them.

use rdy_engine::check::CheckInfo;
use rdy_engine::family::{BuildError, Built, Family};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};

use crate::mtu::{self, MtuCheck};

#[cfg(test)]
mod tests;

/// Every net check this build lists, in catalog order (03 section 3).
static CHECKS: [&CheckInfo; 1] = [&mtu::INFO];

/// The `net` family.
///
/// It lists the checks that are written, which is `net.mtu` ([`MtuCheck`]) so far. `net.egress`,
/// `net.proxy`, `net.tls_intercept`, `net.dns`, `net.registry` and `net.bandwidth` are reserved ids that
/// no family lists yet, so the planner skips them with `not_in_build`. Each ticket that writes one adds
/// its [`CheckInfo`] to the list and its arm to [`Family::build`]. There are no stubs, so the family may
/// be registered in the CLI as it is.
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
            CheckParams::NetMtu(params) => Ok(Built::new(Box::new(MtuCheck::from_params(&params)))),
            _ => Err(BuildError::Unsupported(
                "not a net check this rdy can build".to_owned(),
            )),
        }
    }
}
