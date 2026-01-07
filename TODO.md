- Add an `announce-peer` command?
- Add a multi-query node ID lookup command that implements the node lookup
  described by the Kademlia paper
- Add a command for checking whether a given node ID+IP pair is BEP
  42-compliant
- Replace `set-node-id` with a `gen-node-id [--ip IP]` command and make
  `set-node-id` take an ID to use?
    - Also give `set-node-id` a `--generate` option to automatically combine
      the two commands?

- Give single-packet commands a `-J`/`--json` option for outputting JSON?
    - Represent bytes fields as hexadecimal
    - Represent `InetAddr` values as `HOST:PORT` strings?
- Add an `-x`/`--hex` option for pretty-printing unparsed bytes fields as
  `bytes.fromhex('…')`
    - Just do this for `r.target` (and `t`?) by wrapping the value in a newtype
      with a custom repr?
- Debug-log local IP address and UDP port?

- `lookup`: Add an option to stop iff a certain number of total peers are
  found?
- `lookup`: Implement a "give up" condition so we don't run forever if there
  aren't any peers?
- `lookup`: Rewrite (or add a separate command?) based on the Kademlia paper's
  node lookup routine: Repeatedly query `α` nodes among the `k` closest to the
  target that we haven't yet queried until all `k` closest have been queried,
  then output all peers found along the way
    - Support specifying multiple bootstrap nodes on the command line
- `lookup`: Rename to something with "peers" in it
    - `lookup-peers`?
    - `search-peers`?
    - `peers-search`?

- Add options controlling whether to use IPv4 and/or IPv6
- Add an option for setting the UDP port to use?
    - Separate options for IPv4 and IPv6?
    - Note that, because we set `"ro": 1` in outgoing queries, we won't be
      added to remote nodes' routing tables and thus there's little benefit in
      maintaining a stable inet address
- Add options for setting the local IPv4 & IPv6 addresses to use?
- Store inet options (and timeout) in a config file?
    - Support setting the node ID in the config file as well?

- Support BEP 33?
- Support BEP 44 commands?
    - For "put", this would mean letting the user specify a bencoded data
      value.  How should that be supplied?  Read from a given bencoded file?
- Support BEP 50?

- Fill out `--help` text
- Fill out README
- Put on GitHub?
    - Add a smoke test and CI
