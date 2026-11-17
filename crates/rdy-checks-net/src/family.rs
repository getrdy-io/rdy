//! The net family: the checks that exist so far and how a spec entry builds them.

use rdy_engine::check::CheckInfo;
use rdy_engine::family::{BuildError, Built, Family, HostSet};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};

use crate::egress::{self, EgressCheck};
use crate::mtu::{self, MtuCheck};
use crate::tls_intercept::{self, TlsInterceptCheck};

#[cfg(test)]
mod tests;

/// Every net check this build lists, in catalog order (03 section 3).
static CHECKS: [&CheckInfo; 3] = [&egress::INFO, &mtu::INFO, &tls_intercept::INFO];

/// The `net` family.
///
/// It lists the checks that are written: `net.egress` ([`EgressCheck`]), `net.mtu` ([`MtuCheck`]) and
/// `net.tls_intercept` ([`TlsInterceptCheck`]). A check gets the hosts its own spec entry lists and no
/// others (INV-11): for `net.egress`, its `endpoints`; for `net.tls_intercept`, its `hosts`, or by
/// default the TLS endpoints of the spec's `net.egress` entries.
/// `net.proxy`, `net.dns`, `net.registry` and `net.bandwidth` are reserved ids that
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

    fn build(&self, _: &CheckSpec, params: CheckParams, spec: &Spec) -> Result<Built, BuildError> {
        match params {
            CheckParams::NetEgress(params) => {
                let hosts = HostSet::new(params.endpoints.iter().map(|e| e.target.clone()));
                Ok(Built::new(Box::new(EgressCheck::new(params))).with_hosts(hosts))
            }
            CheckParams::NetMtu(params) => Ok(Built::new(Box::new(MtuCheck::from_params(&params)))),
            CheckParams::NetTlsIntercept(params) => {
                let (hosts, dropped) = tls_intercept::hosts_for(&params, spec);
                let set = HostSet::new(hosts.iter().cloned());
                let check = TlsInterceptCheck::new(&params, hosts, dropped).map_err(|reason| {
                    BuildError::Unsupported(format!("expected_issuer does not compile: {reason}"))
                })?;
                Ok(Built::new(Box::new(check)).with_hosts(set))
            }
            _ => Err(BuildError::Unsupported(
                "not a net check this rdy can build".to_owned(),
            )),
        }
    }
}
