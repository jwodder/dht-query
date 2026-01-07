|repostatus| |license|

.. |repostatus| image:: https://www.repostatus.org/badges/latest/concept.svg
    :target: https://www.repostatus.org/#concept
    :alt: Project Status: Concept – Minimal or no implementation has been done
          yet, or the repository is only intended to be a limited example,
          demo, or proof-of-concept.

.. |license| image:: https://img.shields.io/github/license/jwodder/dht-query.svg
    :target: https://opensource.org/licenses/MIT
    :alt: MIT License

`GitHub <https://github.com/jwodder/dht-query>`_
| `Issues <https://github.com/jwodder/dht-query/issues>`_

``dht-query`` is a Python program for making simple, low-level queries to the
BitTorrent_ `Mainline Distributed Hash Table (DHT) <DHT_>`_.  It implements the
following BEPs_ as much as possible:

- `BEP 5: DHT Protocol <https://www.bittorrent.org/beps/bep_0005.html>`_
- `BEP 32: IPv6 extension for DHT
  <https://www.bittorrent.org/beps/bep_0032.html>`_
- `BEP 42: DHT Security Extension
  <https://www.bittorrent.org/beps/bep_0042.html>`_
- `BEP 43: Read-only DHT Nodes
  <https://www.bittorrent.org/beps/bep_0043.html>`_
- `BEP 51: DHT Infohash Indexing
  <https://www.bittorrent.org/beps/bep_0051.html>`_

``dht-query`` does not run an actual DHT node or keep track of a routing table;
it merely sends query messages (marked as coming from a read-only_ node) and
receives their responses, and no state (other than the node ID) is preserved
across program invocations, not even the local bind address.

.. _BitTorrent: https://en.wikipedia.org/wiki/BitTorrent
.. _DHT: https://en.wikipedia.org/wiki/Mainline_DHT
.. _BEPs: https://www.bittorrent.org/beps/bep_0000.html
.. _read-only: https://www.bittorrent.org/beps/bep_0043.html

Installation
============
``dht-query`` requires Python 3.10 or higher.  Just use `pip
<https://pip.pypa.io>`_ for Python 3 (You have pip, right?) to install it::

    python3 -m pip install git+https://github.com/jwodder/dht-query.git


Usage
=====

::

    dht-query <subcommand> <args> …

The ``dht-query`` command has a number of subcommands, documented below.
Before you can run any querying subcommands, you must invoke the
``set-node-id`` subcommand in order to generate a node ID for ``dht-query`` to
use in outgoing queries.  The node ID is saved locally in a file whose location
depends on your OS:

=======  =============================================================
Linux    ``~/.local/state/dht-query/node-id.dat``
         or ``$XDG_STATE_HOME/dht-query/node-id.dat``
macOS    ``~/Library/Application Support/dht-query/node-id.dat``
Windows  ``%USERPROFILE%\AppData\Local\jwodder\dht-query\node-id.dat``
=======  =============================================================

All query methods take an optional ``-t``/``--timeout`` option for giving the
maximum amount of time in seconds to wait for a reply to a query.  The default
timeout is 15 seconds.

In the below command synopses, different types of arguments are represented as
follows:

``<host>:<port>``
    A pair of a remote host address and a port on that host, separated by a
    colon.  ``<host>`` may be a domain name, an IPv4 address, or an IPv6
    address.  In the case of an IPv6 address, the argument must be formatted as
    ``[<host>]:<port>``.

``<info-hash>``
    A 20-byte info hash of a torrent, specified on the command line as 40
    hexadecimal digits

``<node-id>``
    A 20-byte ID of a DHT node, specified on the command line as 40 hexadecimal
    digits

``error``
---------

::

    dht-query error [-t <timeout>] <host>:<port>

Send a query with an invalid method to the given node to see how it reacts.

``find-node``
-------------
::

    dht-query find-node [-t <timeout>] [--want4] [--want6] <host>:<port> <node-id>

Send a "find_node" query for the given node ID to the given node and
pretty-print the decoded response.

The ``--want4`` and/or ``--want6`` options can be supplied to explicitly
request IPv4 and/or IPv6 nodes from the remote node regardless of which IP
version we're communicating over.

``get-node-id``
---------------

::

    dht-query get-node-id

Print out the locally-stored node ID in hexadecimal.

``get-peers``
-------------

::

    dht-query get-peers [-t <timeout>] [--want4] [--want6] <host>:<port> <info-hash>

Send a "get_peers" query for the given infohash to the given node and
pretty-print the decoded response.

The ``--want4`` and/or ``--want6`` options can be supplied to explicitly
request IPv4 and/or IPv6 nodes from the remote node regardless of which IP
version we're communicating over.

``lookup``
----------

::

    dht-query lookup [<options>] <info-hash>

Perform a simple multiquery search for peers downloading the torrent with the
given infohash.  An initial "get_peers" query is sent to a bootstrap node, and
then we repeatedly query the closest known node that hasn't yet been queried
until we get one or more peers from a node whose ID matches the infohash in
some number of leading bits.  The peers returned from the final response (or
all peers found if ``-a`` is given) are then printed out in ``<host>:<port>``
format.

Options
^^^^^^^

-a, --all-peers                 Print out all peers found in the process rather
                                than just those returned in the last response.

-B ADDRESS, --bootstrap-node ADDRESS
                                Use the node at ``ADDRESS`` (given in
                                ``<host>:<port>`` format) as the bootstrap
                                node.  The default bootstrap node is
                                ``router.bittorrent.com:6881``.

-o FILE, --outfile FILE         Write the found peers to ``FILE`` instead of
                                standard output

-s INT, --similarity INT        Don't stop until we've gotten peers from a node
                                whose ID matches the target info hash in the
                                first ``INT`` or more bits [default: 10]

-t TIMEOUT, --timeout TIMEOUT
                                Specify the maximum number of seconds to wait
                                for a reply to a query [default: 15]

``ping``
--------

::

    dht-query ping [-t <timeout>] <host>:<port>

Send a "ping" query to the given node and pretty-print the decoded response.

``sample-infohashes``
---------------------

::

    dht-query sample-infohashes [-t <timeout>] <host>:<port> <node-id>

Send a "sample_infohashes" query to the given node and pretty-print the decoded
response.  The ``<node-id>`` argument is used in the query as the "target"
field for searching the node ID space at the same time.

``set-node-id``
---------------

::

    dht-query set-node-id [--ip <ip>]

Randomly generate a new node ID to send in outgoing queries, print it out in
hexadecimal, and store it locally; see above for the file path at which the
node ID is saved.  If the ``--ip`` option is given, the new ID will be valid
for the given IPv4 or IPv6 address according to `BEP 42`_.

.. _BEP 42: https://www.bittorrent.org/beps/bep_0042.html
