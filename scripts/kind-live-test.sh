#!/bin/sh
# kind-live-test.sh: set up a cluster for the live tests of rdy-checks-k8s and run them (M1-108, ADR 0039).
#
# Usage: KUBECONFIG=<admin kubeconfig> RDY_LIVE_EXPECT_MINOR=1.35 scripts/kind-live-test.sh
#
# The kind workflow (.github/workflows/kind.yml) creates the cluster and calls this. You can run it by
# hand against a kind cluster too: `kind create cluster`, then this script.
#
# What it does:
#   1. Creates the namespace rdy-live with Pod Security `restricted` on enforce, audit and warn, and
#      shows that the server refuses a privileged pod there (a server-side dry run) and admits a pod that
#      meets `restricted`.
#   2. Applies examples/rbac/rdy-readonly.yaml and builds a kubeconfig of its service account, as the
#      comments of that file say, then checks with `kubectl auth can-i` that it is read-only.
#   3. Runs the ignored tests of crates/rdy-checks-k8s/tests/live_cluster.rs with cargo-nextest.
#
# It deletes the namespaces rdy-live and rdy-system and the rdy-readonly roles, before and after. So it
# refuses to run unless the current context is named kind-* and its API server is on this machine
# (127.0.0.1, localhost or [::1], where kind puts it), or RDY_LIVE_ALLOW_ANY_CLUSTER=1 is set.
# Needs: kubectl 1.31 or newer (or KUBECTL=<path>), cargo-nextest, base64.
# Exit:  0 all steps pass, 1 a step failed, 64 usage error.

set -eu
umask 077

NS=rdy-live
KUBECTL=${KUBECTL:-kubectl}

die() {
    echo "kind-live-test: $*" >&2
    exit 1
}

usage() {
    echo "kind-live-test: $*" >&2
    echo "usage: KUBECONFIG=<admin kubeconfig> RDY_LIVE_EXPECT_MINOR=1.35 scripts/kind-live-test.sh" >&2
    exit 64
}

# Every kubectl call has a time limit, so a hung API server fails the step and does not wait for the job
# timeout. `kw` is for calls that watch (a delete that waits, `wait`): the request timeout cuts a watch,
# so those get a longer one.
k() {
    "$KUBECTL" --request-timeout=30s "$@"
}
kw() {
    "$KUBECTL" --request-timeout=150s "$@"
}

[ -n "${KUBECONFIG:-}" ] || usage "KUBECONFIG is not set. Point it at the kubeconfig of the test cluster."
[ -n "${RDY_LIVE_EXPECT_MINOR:-}" ] || usage "RDY_LIVE_EXPECT_MINOR is not set. Name the Kubernetes minor of the cluster, for example 1.35."
command -v "$KUBECTL" > /dev/null 2>&1 || usage "kubectl was not found. Install it or set KUBECTL=<path>."
cargo nextest --version > /dev/null 2>&1 || usage "cargo-nextest was not found. Install it with: cargo install cargo-nextest --locked"

root=$(cd "$(dirname "$0")/.." && pwd)
rbac="$root/examples/rbac/rdy-readonly.yaml"
[ -f "$rbac" ] || die "$rbac is missing. Run this from a full clone of the repository."

context=$(k config current-context) || die "kubectl has no current context in $KUBECONFIG."
server=$(k config view --minify -o jsonpath='{.clusters[0].cluster.server}') ||
    die "kubectl cannot read the server of context '$context'."
# The host of the server URL, without scheme, path or port. kind listens on the loopback address.
host=${server#*://}
host=${host%%/*}
local_server=no
case "$host" in
    127.0.0.1 | 127.0.0.1:* | localhost | localhost:* | '[::1]' | '[::1]':*) local_server=yes ;;
esac
case "$context" in
    kind-*) ;;
    *)
        [ "${RDY_LIVE_ALLOW_ANY_CLUSTER:-}" = 1 ] ||
            die "the current context is '$context', not kind-*. This script deletes the namespaces $NS and rdy-system. Use a kind cluster, or set RDY_LIVE_ALLOW_ANY_CLUSTER=1 if you mean it."
        ;;
esac
[ "$local_server" = yes ] || [ "${RDY_LIVE_ALLOW_ANY_CLUSTER:-}" = 1 ] ||
    die "the server of context '$context' is '$server', which is not on this machine (127.0.0.1, localhost or [::1]). A kind cluster listens there. This script deletes the namespaces $NS and rdy-system. Use a kind cluster, or set RDY_LIVE_ALLOW_ANY_CLUSTER=1 if you mean it."
echo "cluster: context $context, server host $host, expected minor $RDY_LIVE_EXPECT_MINOR"

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rdy-live.XXXXXX")
cleanup() {
    k delete -f "$rbac" --ignore-not-found --wait=false > /dev/null 2>&1 || true
    k delete namespace "$NS" --ignore-not-found --wait=false > /dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

# Start clean, so a second run on the same cluster proves the same thing. The namespace deletes wait,
# so the create below does not race a namespace that is still terminating.
kw delete -f "$rbac" --ignore-not-found > /dev/null
kw delete namespace "$NS" --ignore-not-found > /dev/null

echo "step 1: namespace $NS, Pod Security restricted"
k apply -f - > /dev/null << EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NS
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
EOF
enforce=$(k get namespace "$NS" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')
[ "$enforce" = restricted ] || die "namespace $NS has enforce='$enforce', not restricted."

# The dry runs below need the service account 'default', which the controller manager creates a moment
# after the namespace.
kw wait --for=create -n "$NS" serviceaccount/default --timeout=30s > /dev/null ||
    die "the service account 'default' did not appear in $NS within 30 seconds. Is the controller manager healthy?"

# A server-side dry run runs admission and stores nothing, so no image is pulled and no pod starts.
cat > "$work/privileged.yaml" << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: psa-probe-privileged
spec:
  containers:
    - name: probe
      image: registry.k8s.io/pause:3.10
      securityContext:
        privileged: true
EOF
cat > "$work/restricted.yaml" << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: psa-probe-restricted
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: registry.k8s.io/pause:3.10
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
EOF
if refused=$(k apply --dry-run=server -n "$NS" -f "$work/privileged.yaml" 2>&1); then
    die "the server admitted a privileged pod in $NS. Pod Security is not enforcing restricted. Output: $refused"
fi
case "$refused" in
    *'violates PodSecurity "restricted:latest"'*) echo "  privileged pod refused: restricted is enforced" ;;
    *) die "the privileged pod was refused, but not by Pod Security restricted. Output: $refused" ;;
esac
if ! admitted=$(k apply --dry-run=server -n "$NS" -f "$work/restricted.yaml" 2>&1); then
    die "the server refused a pod that meets restricted in $NS. Output: $admitted"
fi
echo "  pod that meets restricted admitted"

echo "step 2: the rdy-readonly service account"
k apply -f "$rbac" > /dev/null
token=$(k -n rdy-system create token rdy-readonly --duration 1h)
ca_data=$(k config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
[ -n "$ca_data" ] || die "the admin kubeconfig has no certificate-authority-data for its cluster. kind writes it; for another cluster, set up the read-only kubeconfig by hand."
# The kubeconfig is written from shell variables, so the token never appears on a command line, where
# other users of the machine could read it with ps. The file is private (umask 077) and the cleanup
# removes it.
ro="$work/ro.kubeconfig"
cat > "$ro" << EOF
apiVersion: v1
kind: Config
clusters:
  - name: c
    cluster:
      server: "$server"
      certificate-authority-data: "$ca_data"
users:
  - name: rdy
    user:
      token: "$token"
contexts:
  - name: c
    context:
      cluster: c
      user: rdy
current-context: c
EOF

# `can-i` prints yes or no and exits 1 on no, so read the text and not the status.
can() {
    k --kubeconfig="$ro" auth can-i "$@" 2> /dev/null || true
}
# The first answer can come before the role binding reaches the authorizer. Allow 30 seconds.
tries=0
until [ "$(can list nodes)" = yes ]; do
    tries=$((tries + 1))
    [ "$tries" -lt 30 ] || die "the rdy-readonly kubeconfig cannot list nodes after 30 seconds. Check the apply of $rbac and the token."
    sleep 1
done
[ "$(can create pods -n "$NS")" = no ] || die "the rdy-readonly kubeconfig can create pods. The role is not read-only."
[ "$(can get secrets -n kube-system)" = no ] || die "the rdy-readonly kubeconfig can read Secrets. The role is not read-only."
echo "  read-only: lists nodes, cannot create pods or read Secrets"

echo "step 3: live tests (cargo nextest, ignored tests of live_cluster)"
RDY_READONLY_KUBECONFIG="$ro"
RDY_LIVE_NAMESPACE="$NS"
export RDY_READONLY_KUBECONFIG RDY_LIVE_NAMESPACE RDY_LIVE_EXPECT_MINOR
cd "$root"
cargo nextest run --locked -p rdy-checks-k8s --test live_cluster \
    --run-ignored only --profile ci --no-tests=fail --no-capture
