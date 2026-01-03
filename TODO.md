- Add a command for checking whether a given node ID+IP pair is BEP
  42-compliant
- Add a command for finding peers for a given info hash via the following:
    - Start by querying router.bittorrent.com:6881
    - Repeatedly send "get_peers" queries (with `"want": ["n4", "n6"]`) to the
      closest known node (skipping nodes that have already been queried) until
      one of the following:
        - A node returns only "values", no "nodes" (?)
        - We get "values" from a node whose ID equals the info hash in the
          first `n` bits for some `n` (settable on the command line?)
    - Write all peers returned from the most recent node (and peers from
      previous nodes?  If a CLI option is given?) to stdout or a given file in
      `IP:PORT` format

- `lookup`:
    - Add `--timeout` option
    - Add option for setting similarity target
    - Include time in logging output
    - Add option for outputting all peers found in session
