- Add a command for checking whether a given node ID+IP pair is BEP
  42-compliant
    - Give `get-node-id` an `--ip IP` option to make it also check whether our
      node ID is compliant
- `lookup`:
    - Support querying multiple nodes at once via worker tasks?
    - Add an option to stop iff a certain number of total peers are found?
    - Output peers in sorted order? (IPv4 before IPv6, each type sorted by (IP
      bytes, port))
- Fill out `--help` text
- Fill out README?
- Put on GitHub?
- Pretty-print node IDs as `NodeID("hexstring")`?
