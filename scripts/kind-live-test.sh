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
# refuses to run unless the current context is named kind-*, or RDY_LIVE_ALLOW_ANY_CLUSTER=1 is set.
# Needs: kubectl (or KUBECTL=<path>), cargo-nextest, base64.
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

[ -n "${KUBECONFIG:-}" ] || usage "KUBECONFIG is not set. Point it at the kubeconfig of the test cluster."
[ -n "${RDY_LIVE_EXPECT_MINOR:-}" ] || usage "RDY_LIVE_EXPECT_MINOR is not set. Name the Kubernetes minor of the cluster, for example 1.35."
command -v "$KUBECTL" > /dev/null 2>&1 || usage "kubectl was not found. Install it or set KUBECTL=<path>."

root=$(cd "$(dirname "$0")/.." && pwd)
rbac="$root/examples/rbac/rdy-readonly.yaml"
[ -f "$rbac" ] || die "$rbac is missing. Run this from a full clone of the repository."

context=$("$KUBECTL" config current-context) || die "kubectl has no current context in $KUBECONFIG."
case "$context" in
    kind-*) ;;
    *)
        [ "${RDY_LIVE_ALLOW_ANY_CLUSTER:-}" = 1 ] ||
            die "the current context is '$context', not kind-*. This script deletes the namespaces $NS and rdy-system. Use a kind cluster, or set RDY_LIVE_ALLOW_ANY_CLUSTER=1 if you mean it."
        ;;
esac
echo "cluster: context $context, expected minor $RDY_LIVE_EXPECT_MINOR"

work=$(mktemp -d)
cleanup() {
    "$KUBECTL" delete -f "$rbac" --ignore-not-found --wait=false > /dev/null 2>&1 || true
    "$KUBECTL" delete namespace "$NS" --ignore-not-found --wait=false > /dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

# Start clean, so a second run on the same cluster proves the same thing. The namespace deletes wait,
# so the create below does not race a namespace that is still terminating.
"$KUBECTL" delete -f "$rbac" --ignore-not-found > /dev/null
"$KUBECTL" delete namespace "$NS" --ignore-not-found > /dev/null

echo "step 1: namespace $NS, Pod Security restricted"
"$KUBECTL" apply -f - > /dev/null << EOF
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
enforce=$("$KUBECTL" get namespace "$NS" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')
[ "$enforce" = restricted ] || die "namespace $NS has enforce='$enforce', not restricted."

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
if refused=$("$KUBECTL" apply --dry-run=server -n "$NS" -f "$work/privileged.yaml" 2>&1); then
    die "the server admitted a privileged pod in $NS. Pod Security is not enforcing restricted. Output: $refused"
fi
case "$refused" in
    *'violates PodSecurity "restricted:latest"'*) echo "  privileged pod refused: restricted is enforced" ;;
    *) die "the privileged pod was refused, but not by Pod Security restricted. Output: $refused" ;;
esac
if ! admitted=$("$KUBECTL" apply --dry-run=server -n "$NS" -f "$work/restricted.yaml" 2>&1); then
    die "the server refused a pod that meets restricted in $NS. Output: $admitted"
fi
echo "  pod that meets restricted admitted"

echo "step 2: the rdy-readonly service account"
"$KUBECTL" apply -f "$rbac" > /dev/null
token=$("$KUBECTL" -n rdy-system create token rdy-readonly --duration 1h)
server=$("$KUBECTL" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
"$KUBECTL" config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' |
    base64 -d > "$work/ca.crt"
[ -s "$work/ca.crt" ] || die "the admin kubeconfig has no certificate-authority-data for its cluster. kind writes it; for another cluster, set up the read-only kubeconfig by hand."
ro="$work/ro.kubeconfig"
"$KUBECTL" config --kubeconfig="$ro" set-cluster c --server="$server" \
    --certificate-authority="$work/ca.crt" --embed-certs > /dev/null
"$KUBECTL" config --kubeconfig="$ro" set-credentials rdy --token="$token" > /dev/null
"$KUBECTL" config --kubeconfig="$ro" set-context c --cluster=c --user=rdy > /dev/null
"$KUBECTL" config --kubeconfig="$ro" use-context c > /dev/null

# `can-i` prints yes or no and exits 1 on no, so read the text and not the status.
can() {
    "$KUBECTL" --kubeconfig="$ro" auth can-i "$@" 2> /dev/null || true
}
[ "$(can list nodes)" = yes ] || die "the rdy-readonly kubeconfig cannot list nodes. Check the apply of $rbac and the token."
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
