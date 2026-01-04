- Add a command for checking whether a given node ID+IP pair is BEP
  42-compliant
    - Give `get-node-id` an `--ip IP` option to make it also check whether our
      node ID is compliant
- `lookup`:
    - Add an option to stop iff a certain number of total peers are found?
    - Output peers in sorted order? (IPv4 before IPv6, each type sorted by (IP
      bytes, port))
- Add a dedicated `InfoHash` type?
- Replace `parse_info_hash()` with an `InfoHashParam` type?
- Replace/wrap `InetAddr.parse()` with an `InetAddrParam` type?
- `set-node-id`: Support passing IPv6 addresses to `--ip`
- Add a `find-node` command?

- Fill out `--help` text
- Fill out README
- Put on GitHub?
