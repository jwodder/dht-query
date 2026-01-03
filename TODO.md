- Support IPv6 hosts
- Stop hardcoding our node ID
    - Store it in a platformdirs dir?
- Add commands for managing our node ID:
    - Add a command for setting our node ID to a BEP 42-compatible node ID,
      using either a given IP address or https://httpbin.org/ip
        - After updating our node ID with this, try pinging the failed
          bootstrap nodes again
    - Add a command for setting our node ID to just a random 20 bytes
    - Add a command for displaying our node ID
- Add a command for checking whether a given node ID+IP pair is BEP
  42-compliant
