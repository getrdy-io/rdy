You can use this page to fix each cluster finding. Each section names one check, what it measures, what it reads from the cluster and the fix text that rdy prints for it.

rdy reads the cluster through the kubeconfig you give it, or the one on your machine. It reads only what each check lists. The access reviews it sends change nothing in the cluster. Without a kubeconfig, each Kubernetes check is skipped, and the result says how to point rdy at a cluster.

The Remediation text is the general fix for the check. A finding can carry a more specific fix of its own. When it does, rdy prints that fix instead. Where the fix names a command, run it against the same cluster you checked.

The API reads line lists each Kubernetes API resource the check reads, the verbs it uses and what rdy keeps from the response. The Reads line lists local paths. Kubernetes checks read no local paths, so it says none. Neither list splits by operating system. The API reads line does not list the three self-review requests that `k8s.access` and `k8s.rbac` send, so those checks may show none.
