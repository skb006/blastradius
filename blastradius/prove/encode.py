"""Encode the agent graph into segval's network IR.

This is the load-bearing trick of stage 4, so it is worth stating plainly:
**we do not fork the prover, we adapt at the boundary.**

    node       -> zone (a synthetic /24)
    hop (u,v)  -> its own device, so each hop has its own filter
    capability -> destination port   (1 = read, 2 = write)
    grant      -> ACCEPT rule on that hop's device
    absence    -> the device's DROP default

The encoding preserves rather than weakens the machinery. segval partitions
the 5-tuple into atomic predicates; under this mapping that becomes a
partition over (principal x resource x capability), which is exactly the
partition stage 4 needs. Exhaustive "for all requests" queries stay
tractable, and the soundness argument is inherited rather than re-derived.

**Why capability and not operation is the port.** A path has a different
operation at each hop — ``create_issue`` then ``repo`` — and one 5-tuple
cannot carry both. What *is* uniform along the path is the capability class,
and it is also the thing worth proving: "can this agent effect a write on
that principal". The concrete tool and scope names ride along in each rule's
``raw`` field, so the witness stays specific even though the query is coarse.

**Why one device per hop.** A packet's addresses are constant end to end, so
a rule cannot identify its hop by CIDR — an earlier encoding tried, and the
tool hop was silently ignored, making every graph look violated. Giving each
hop its own device gives it its own filter; the rule then asks only "does
this hop admit this capability?", and ``reach_multi_hop`` accepts a path
exactly when every hop on it does. That is the composition rule blast radius
needs, and it is the property ``test_read_only_tools_cannot_reach_write``
pins down.

Limits, stated rather than discovered later: 65534 nodes (address space) and
two capability classes (ports). Both are far beyond any real deployment.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from .graph import AgentGraph, Edge

PORT_READ = 1
PORT_WRITE = 2
CAPABILITY_PORT = {"read": PORT_READ, "write": PORT_WRITE}

POLICY_DEVICE = "agent-policy"
_BASE = ipaddress.IPv4Address("10.0.0.0")


class SegvalUnavailable(RuntimeError):
    """segval is not installed. Stage 4 is an optional extra."""


def _require_segval():
    try:
        from segval.core.rule import PortRange, Rule
        from segval.model.graph import build_graph as segval_build_graph
        from segval.model.loader import Network
        from segval.model.schema import DeviceSpec, RouteSpec, TopologySpec, ZoneSpec
        from segval.parsers.iptables import ParsedConfig
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise SegvalUnavailable(
            "the prover is an optional extra: install segval "
            "(pip install 'blastradius[prove]') to run `blastradius prove`"
        ) from exc
    return {
        "Rule": Rule, "PortRange": PortRange, "build_graph": segval_build_graph, "Network": Network,
        "DeviceSpec": DeviceSpec, "RouteSpec": RouteSpec,
        "TopologySpec": TopologySpec, "ZoneSpec": ZoneSpec,
        "ParsedConfig": ParsedConfig,
    }


@dataclass
class Encoding:
    """The encoded network plus everything needed to decode a witness."""

    network: Any
    zone_of: dict[str, str]                 # node id -> zone name
    node_of: dict[str, str]                 # zone name -> node id
    address_of: dict[str, ipaddress.IPv4Address]
    edge_by_index: dict[int, Edge]

    def address(self, node_id: str) -> ipaddress.IPv4Address:
        return self.address_of[self.zone_of[node_id]]

    def zone(self, node_id: str) -> str:
        return self.zone_of[node_id]


def _zone_name(node_id: str) -> str:
    """segval zone names must be plain identifiers; node ids carry colons."""
    return node_id.replace(":", "__").replace("/", "_").replace(" ", "_")


def _subnet(index: int) -> ipaddress.IPv4Network:
    if index > 65533:
        raise ValueError("more nodes than the encoding's address space allows")
    return ipaddress.IPv4Network(
        (int(_BASE) + (index + 1) * 256, 24)  # 10.0.1.0/24, 10.0.2.0/24, ...
    )


def encode(graph: AgentGraph) -> Encoding:
    """Build an in-memory segval Network equivalent to ``graph``."""
    seg = _require_segval()

    zone_of: dict[str, str] = {}
    node_of: dict[str, str] = {}
    address_of: dict[str, ipaddress.IPv4Address] = {}
    zone_cidr: dict[str, Any] = {}

    for index, node_id in enumerate(sorted(graph.nodes)):
        zname = _zone_name(node_id)
        subnet = _subnet(index)
        zone_of[node_id] = zname
        node_of[zname] = node_id
        address_of[zname] = next(subnet.hosts())
        zone_cidr[zname] = subnet

    edge_by_index: dict[int, Edge] = {}

    # One device per hop. segval shares a single Filter across every route
    # that names the same device, so distinct hops need distinct devices —
    # otherwise every rule would be evaluated on every edge.
    any_net = ipaddress.IPv4Network("0.0.0.0/0")
    caps_by_pair: dict[tuple[str, str], list[tuple[int, Edge]]] = {}

    for index, edge in enumerate(graph.edges):
        if edge.src not in zone_of or edge.dst not in zone_of:
            continue
        edge_by_index[index] = edge
        caps_by_pair.setdefault((edge.src, edge.dst), []).append((index, edge))

    parsed: dict[str, Any] = {}
    routes: list[Any] = []

    for (src_id, dst_id), members in sorted(caps_by_pair.items()):
        device = f"hop__{_zone_name(src_id)}__{_zone_name(dst_id)}"
        rules: list[Any] = []
        pr = seg["PortRange"]

        for index, edge in members:
            # The packet's addresses are fixed end to end, so a per-hop rule
            # cannot distinguish hops by CIDR. The hop is identified by which
            # device the rule sits on; the rule itself asks only "does this
            # hop admit this capability?". reach_multi_hop then accepts a path
            # exactly when EVERY hop on it admits the capability — which is
            # the composition rule blast radius needs.
            ports = ([pr(PORT_READ, PORT_READ), pr(PORT_WRITE, PORT_WRITE)]
                     if edge.is_write else [pr(PORT_READ, PORT_READ)])
            rules.append(seg["Rule"](
                action="accept",
                proto="tcp",
                src_cidr=any_net,
                dst_cidr=any_net,
                src_ports=[],
                dst_ports=ports,
                states={"NEW"},
                chain="FORWARD",
                # The index prefix is how a witness is decoded back to an edge.
                raw=f"#{index} {edge.src} --[{edge.operation}]--> {edge.dst}",
                source_file=str(edge.origin) if edge.origin else "<derived>",
                line_number=index,
            ))

        parsed[device] = seg["ParsedConfig"](
            rules=rules, default_policies={"FORWARD": "drop"},
            source_file=f"<hop {src_id} -> {dst_id}>")
        routes.append(seg["RouteSpec"](
            src=zone_of[src_id], via=device, dst=[zone_of[dst_id]]))

    if not parsed:
        parsed[POLICY_DEVICE] = seg["ParsedConfig"](
            rules=[], default_policies={"FORWARD": "drop"}, source_file="<empty>")

    gateway = sorted(parsed)[0]
    topology = seg["TopologySpec"](
        zones={z: seg["ZoneSpec"](cidr=cidr, gateway=gateway)
               for z, cidr in zone_cidr.items()},
        devices={name: seg["DeviceSpec"](configs=[]) for name in parsed},
        routes=routes,
    )
    network = seg["Network"](
        topology=topology,
        graph=seg["build_graph"](topology, parsed),
        parsed_configs=parsed,
    )
    return Encoding(network, zone_of, node_of, address_of, edge_by_index)


def decode_edge(raw: str, encoding: Encoding) -> Edge | None:
    """Recover the agent-level edge a segval rule came from."""
    if not raw.startswith("#"):
        return None
    head = raw[1:].split(" ", 1)[0]
    try:
        return encoding.edge_by_index.get(int(head))
    except ValueError:
        return None
