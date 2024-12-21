
- `openstack acm provision [--network network] [-n namespace] <infraenv> <NODE> [<NODE> ...]`

  Boots node using `isoDownloadURL` from given infraenv.

- `openstack acm sync-metadata [-n namespace] <infraenv>`

  Update names of agents in infraenv to match esi node names.

- `openstack acm port-forward-all [--kind (loadbalancer|nodeport|all)] [-n namespace] [--internal-ip address] external_ip`

  Create port-forwards for all NodePort services in <cluster> namespace.

- `openstack acm port-forward [-n namespace] [--internal-ip address] service external_ip`

  Create a port forward for a single service. `--internal-ip` is only necessry for NodePort services.

