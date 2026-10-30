//! The fix text of `k8s.storageclass`. Short, specific, and each command is on the fix-text allow-list
//! (`rdy_engine::fixtext`; the tests of this module run every text through it).
//!
//! Names that come from the cluster are passed in as they came. A name that goes into a command passes
//! through [`command_arg`], which keeps only an untruncated DNS-1123 name and otherwise writes `<class>`,
//! `<claim>` or `<namespace>`, so a hostile name cannot become a flag.

use rdy_spec::check::AccessMode;

use super::facts::command_arg;

/// The fix for a default class that is missing.
pub(super) fn mark_default(name: &str) -> String {
    let name = command_arg(name, "<class>");
    format!(
        "Mark one class as the default: `kubectl patch storageclass {name} -p '{{\"metadata\":{{\"annotations\":{{\"storageclass.kubernetes.io/is-default-class\":\"true\"}}}}}}'`."
    )
}

/// The fix for a cluster with no storage class at all.
pub(super) fn no_classes() -> String {
    "The cluster has no storage class. Install a CSI driver, create a StorageClass on it, then mark it as the default. List what exists with `kubectl get storageclass`.".to_owned()
}

/// The fix for a class that the spec names and the cluster lacks.
pub(super) fn create_class(name: &str) -> String {
    format!(
        "Create a class called `{name}`, or ask the vendor which class their install expects. List what exists with `kubectl get storageclass`."
    )
}

/// The fix for more than one default: unmark every default but the one to keep.
pub(super) fn unmark_defaults(others: &[String]) -> String {
    let commands: Vec<String> = others
        .iter()
        .map(|name| {
            let name = command_arg(name, "<class>");
            format!(
                "`kubectl patch storageclass {name} -p '{{\"metadata\":{{\"annotations\":{{\"storageclass.kubernetes.io/is-default-class\":\"false\"}}}}}}'`"
            )
        })
        .collect();
    format!(
        "Keep one default and unmark the rest: {}.",
        commands.join(", ")
    )
}

/// The fix for permissions the identity lacked: what to ask for, and the commands that check each.
pub(super) fn grants(commands: &[String], wanted: &[String]) -> String {
    format!(
        "Ask the cluster admin to grant this identity: {}. Check each with {}.",
        wanted.join(", "),
        commands.join(", ")
    )
}

/// The fix for a list rdy read only in part, or could not read for another reason.
pub(super) fn by_hand() -> &'static str {
    "Check by hand what rdy could not read: `kubectl get storageclass`, then `kubectl get csinodes`."
}

/// The fix for a CSI driver that no node has registered and no driver object declares.
pub(super) fn install_driver(driver: &str, class: &str) -> String {
    match driver {
        "ebs.csi.aws.com" => format!(
            "No EBS CSI driver is registered, so PVCs on `{class}` stay Pending. Install it with a role: `eksctl create addon --cluster <cluster> --name aws-ebs-csi-driver --service-account-role-arn <role-arn>`. With EKS Pod Identity (needs the `eks-pod-identity-agent` add-on) use `aws eks create-addon --cluster-name <cluster> --addon-name aws-ebs-csi-driver --pod-identity-associations serviceAccount=ebs-csi-controller-sa,roleArn=<role-arn>`. The role needs the AWS managed policy `AmazonEBSCSIDriverPolicyV2` and a trust relationship for the `ebs-csi-controller-sa` service account."
        ),
        "ebs.csi.eks.amazonaws.com" => format!(
            "EKS Auto Mode runs block storage for you, so there is no add-on to install, and `{class}` can only bind on Auto Mode nodes. Check that the cluster has Auto Mode block storage enabled and that the pod runs on an Auto Mode node: `aws eks describe-cluster --name <cluster>`."
        ),
        "efs.csi.aws.com" => format!(
            "No EFS CSI driver is registered, so PVCs on `{class}` stay Pending. Install it: `eksctl create addon --cluster <cluster> --name aws-efs-csi-driver --service-account-role-arn <role-arn>`."
        ),
        "pd.csi.storage.gke.io" => format!(
            "The persistent disk CSI driver is not registered, so PVCs on `{class}` stay Pending. Enable it: `gcloud container clusters update <cluster> --update-addons=GcePersistentDiskCsiDriver=ENABLED`. GKE Autopilot clusters always have it, so the update does not apply there."
        ),
        "disk.csi.azure.com" => format!(
            "The Azure Disk CSI driver is not registered, so PVCs on `{class}` stay Pending. Enable it: `az aks update -g <resource-group> -n <cluster> --enable-disk-driver`."
        ),
        "file.csi.azure.com" => format!(
            "The Azure Files CSI driver is not registered, so PVCs on `{class}` stay Pending. Enable it: `az aks update -g <resource-group> -n <cluster> --enable-file-driver`."
        ),
        other => format!(
            "No `{other}` CSI driver is registered, so PVCs on `{class}` stay Pending. Install the driver and its node plugin, or mark a class whose driver is installed as the default. See what is installed with `kubectl get csidrivers`."
        ),
    }
}

/// The fix for a driver object whose node plugin has not registered.
pub(super) fn node_plugin(driver: &str) -> String {
    format!(
        "The driver `{driver}` is declared but no node has registered it, so its node plugin may be down. Check that its DaemonSet runs on the nodes: `kubectl get daemonsets -A`, then `kubectl get csinodes`."
    )
}

/// The fix for an access mode the driver does not serve.
pub(super) fn other_driver(mode: AccessMode) -> String {
    let (what, examples) = match mode {
        AccessMode::ReadWriteMany => (
            "ReadWriteMany",
            "a shared file system driver: NFS, EFS, Azure Files, Filestore or CephFS",
        ),
        AccessMode::ReadWriteOncePod => (
            "ReadWriteOncePod",
            "a CSI driver (Kubernetes serves this mode for CSI volumes only)",
        ),
        _ => ("that access mode", "a driver that serves it"),
    };
    format!(
        "Create a class on {examples} so {what} works, mark it as the default, or name it in the product's values."
    )
}

/// The fix for a binding mode that differs from the spec.
pub(super) fn rebind(name: &str, want: &str) -> String {
    let name = command_arg(name, "<class>");
    format!(
        "The binding mode of a class cannot be changed. Copy it with `kubectl get storageclass {name} -o yaml`, set `volumeBindingMode: {want}` in a new class with another name, and mark that one as the default."
    )
}

/// The fix for a class that cannot grow.
pub(super) fn allow_expansion(name: &str) -> String {
    let name = command_arg(name, "<class>");
    format!(
        "Allow growing volumes: `kubectl patch storageclass {name} -p '{{\"allowVolumeExpansion\":true}}'`. The driver must support expansion."
    )
}

/// The fix for a reclaim policy that differs from the spec.
pub(super) fn reclaim(name: &str, want: &str) -> String {
    let name = command_arg(name, "<class>");
    format!(
        "The reclaim policy of a class cannot be changed. Copy it with `kubectl get storageclass {name} -o yaml`, set `reclaimPolicy: {want}` in a new class with another name, and mark that one as the default."
    )
}

/// The fix for claims that wait and whose provisioning failed.
pub(super) fn failing_claims(namespace: &str, claim: &str) -> String {
    let namespace = command_arg(namespace, "<namespace>");
    let claim = command_arg(claim, "<claim>");
    format!(
        "Read why provisioning failed: `kubectl describe pvc {claim} -n {namespace}`. The usual causes are a driver without cloud permissions and a quota."
    )
}
