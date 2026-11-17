You can use this page to fix each cluster finding. Each section names one check, what it measures, what it reads from the cluster and the fix text that rdy prints for it.

rdy reads the cluster through the kubeconfig you give it, or the one on your machine. It reads only what each check lists. The access reviews it sends change nothing in the cluster. Without a kubeconfig, each Kubernetes check is skipped, and the result says how to point rdy at a cluster.

The Remediation text is the general fix for the check. A finding can carry a more specific fix of its own. When it does, rdy prints that fix instead. Where the fix names a command, run it against the same cluster you checked.

The Reads line lists the API paths each check reads. It is one list for every operating system. rdy does not yet list the reads for each system on its own.
