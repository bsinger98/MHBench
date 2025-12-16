"""
Attack graph models and utilities.

Represents attack paths as a graph of (host, user) identity nodes and step edges.
Also provides utilities to compute deduplicated vulnerability installations
based on merge strategies without mutating or removing edges.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Set
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from src.models.vulnerabilities import Vulnerability, MergeStrategy
from src.models.attack_paths import (
    AttackPath,
    LateralMovementStep,
    PrivilegeEscalationStep,
)
from src.models.goals import Goal


class AttackGraphNode(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    host_id: UUID
    user_id: UUID


class AttackGraphEdge(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    from_node_id: UUID
    to_node_id: UUID
    is_lateral_movement: bool
    vulnerability: Optional[Vulnerability] = None


class AttackGraph(BaseModel):
    nodes: Dict[UUID, AttackGraphNode] = Field(default_factory=dict)
    edges: Dict[UUID, AttackGraphEdge] = Field(default_factory=dict)
    adjacency: Dict[UUID, List[UUID]] = Field(default_factory=dict)

    def get_all_edges(self) -> List[AttackGraphEdge]:
        return list(self.edges.values())

    def get_edges_by_ids(self, edge_ids: List[UUID]) -> List[AttackGraphEdge]:
        return [self.edges[edge_id] for edge_id in edge_ids]

    def get_node_edges(self, node_id: UUID) -> List[AttackGraphEdge]:
        from_edges = self.get_edges_from_node(node_id)
        to_edges = self.get_edges_to_node(node_id)
        return from_edges + to_edges

    def get_edges_from_node(self, node_id: UUID) -> List[AttackGraphEdge]:
        return [edge for edge in self.edges.values() if edge.from_node_id == node_id]

    def get_edges_to_node(self, node_id: UUID) -> List[AttackGraphEdge]:
        return [edge for edge in self.edges.values() if edge.to_node_id == node_id]

    def get_node_by_id(self, node_id: UUID) -> Optional[AttackGraphNode]:
        return self.nodes.get(node_id)

    def get_node_by_identity(
        self, host_id: UUID, user_id: UUID
    ) -> Optional[AttackGraphNode]:
        for node in self.nodes.values():
            if node.host_id == host_id and node.user_id == user_id:
                return node
        return None


def _get_or_create_node(
    nodes_by_identity: Dict[Tuple[UUID, UUID], AttackGraphNode],
    nodes: Dict[UUID, AttackGraphNode],
    host_id: UUID,
    user_id: UUID,
) -> AttackGraphNode:
    key = (host_id, user_id)
    existing = nodes_by_identity.get(key)
    if existing is not None:
        return existing
    node = AttackGraphNode(host_id=host_id, user_id=user_id)
    nodes_by_identity[key] = node
    nodes[node.id] = node
    return node


def build_attack_graph(paths: List[AttackPath]) -> AttackGraph:
    """Construct an attack graph from linear attack paths.

    - Nodes represent (host_id, user_id) identities
    - Edges represent step transitions and carry the step's vulnerability
    """
    graph = AttackGraph()
    nodes_by_identity: Dict[Tuple[UUID, UUID], AttackGraphNode] = {}

    for path in paths:
        # Ensure a node for the starting context
        current_node = _get_or_create_node(
            nodes_by_identity,
            graph.nodes,
            host_id=path.start_host_id,
            user_id=path.start_user_id,
        )

        for step in path.steps:
            if isinstance(step, LateralMovementStep):
                next_node = _get_or_create_node(
                    nodes_by_identity,
                    graph.nodes,
                    host_id=step.to_host_id,
                    user_id=step.to_user_id,
                )
                edge = AttackGraphEdge(
                    from_node_id=current_node.id,
                    to_node_id=next_node.id,
                    is_lateral_movement=True,
                    vulnerability=step.vulnerability,
                )
                graph.edges[edge.id] = edge
                graph.adjacency.setdefault(current_node.id, []).append(edge.id)
                current_node = next_node
            elif isinstance(step, PrivilegeEscalationStep):
                next_node = _get_or_create_node(
                    nodes_by_identity,
                    graph.nodes,
                    host_id=step.host_id,
                    user_id=step.to_user_id,
                )
                edge = AttackGraphEdge(
                    from_node_id=current_node.id,
                    to_node_id=next_node.id,
                    is_lateral_movement=False,
                    vulnerability=step.vulnerability,
                )
                graph.edges[edge.id] = edge
                graph.adjacency.setdefault(current_node.id, []).append(edge.id)
                current_node = next_node

    return graph


def _edge_target_host_id(graph: AttackGraph, edge: AttackGraphEdge) -> UUID:
    """Return the host_id that the edge's vulnerability installs on.

    - For lateral movement, installs on the target host
    - For privilege escalation, installs on the host of the step (same host)
    """
    to_node = graph.nodes[edge.to_node_id]
    if edge.is_lateral_movement:
        return to_node.host_id
    return to_node.host_id


def prune_edges_by_host(graph: AttackGraph) -> AttackGraph:
    """Merge duplicate edges whose vulnerability uses the BY_HOST merge strategy.

    - Only edges with vulnerability.merge_strategy == MergeStrategy.BY_HOST are considered for merging
    - Two edges are considered duplicates if they share (from_node_id, to_node_id,
      vulnerability.type, vulnerability.playbook_path)
    - Keeps the first encountered edge as the representative and drops the rest
    - Updates adjacency to reference only the representative edges

    Returns the same graph instance for convenience.
    """
    if not graph.edges:
        return graph

    for node_id in graph.nodes.keys():
        edges = graph.get_edges_to_node(node_id)

        # Get edges with BY_HOST merge strategy
        by_host_edges = []
        for edge in edges:
            if (
                edge.vulnerability
                and edge.vulnerability.merge_strategy == MergeStrategy.BY_HOST
            ):
                by_host_edges.append(edge)

        # Merge edges with BY_HOST merge strategy
        if len(by_host_edges) > 1:
            # Merge edges with first edge as representative
            representative_edge = by_host_edges[0]
            representative_to_node = graph.nodes[representative_edge.to_node_id]
            for edge in by_host_edges[1:]:
                # If to node is different, redirect edges to representative to node
                to_node = graph.nodes[edge.to_node_id]
                if to_node.id != representative_to_node.id:
                    _merge_to_node(graph, representative_to_node, to_node)

    return graph


def validate_attack_graph(graph: AttackGraph, goals: List[Goal]) -> None:
    """Validate the attack graph."""
    connected, unreachable_nodes = validate_all_nodes_connected(graph)
    if not connected:
        raise Exception(f"Attack graph is not connected: {unreachable_nodes}")

    validate_all_goal_nodes_exist(graph, goals)


def validate_all_goal_nodes_exist(graph: AttackGraph, goals: List[Goal]) -> None:
    """Validate that all goal nodes exist in the attack graph."""
    for goal in goals:
        goal_host_id = goal.target_host_id
        goal_user_id = goal.target_user_id

        node = graph.get_node_by_identity(goal_host_id, goal_user_id)
        if node is None:
            raise Exception(
                f"Goal node {goal_host_id} {goal_user_id} does not exist in the attack graph"
            )


def validate_all_nodes_connected(graph: AttackGraph) -> Tuple[bool, Set[UUID]]:
    """Validate that all nodes in the attack graph are connected.

    Connectivity is evaluated on the underlying undirected graph: an edge
    connects its two endpoints regardless of direction.

    Returns a tuple of (is_connected, unreachable_node_ids).
    """
    if not graph.nodes:
        return True, set()

    # Build undirected adjacency using edges
    undirected_adj: Dict[UUID, Set[UUID]] = {node_id: set() for node_id in graph.nodes}

    for from_node_id, edge_ids in graph.adjacency.items():
        for edge_id in edge_ids:
            edge = graph.edges.get(edge_id)
            if edge is None:
                continue
            undirected_adj[from_node_id].add(edge.to_node_id)
            undirected_adj[edge.to_node_id].add(from_node_id)

    # DFS/BFS from an arbitrary node
    start_node_id = next(iter(graph.nodes))
    visited: Set[UUID] = set()
    stack: List[UUID] = [start_node_id]

    while stack:
        node_id = stack.pop()
        if node_id in visited:
            continue
        visited.add(node_id)
        neighbors = undirected_adj.get(node_id, set())
        for neighbor_id in neighbors:
            if neighbor_id not in visited:
                stack.append(neighbor_id)

    unreachable = set(graph.nodes.keys()) - visited
    return len(unreachable) == 0, unreachable


def _merge_to_node(
    graph: AttackGraph, base_node: AttackGraphNode, node_to_merge: AttackGraphNode
) -> None:
    """Merge the to node into the representative to node."""
    # Redirect edges to representative to node
    to_edges = graph.get_edges_to_node(node_to_merge.id)
    from_edges = graph.get_edges_from_node(node_to_merge.id)

    for edge in to_edges:
        edge.to_node_id = base_node.id

    for edge in from_edges:
        edge.from_node_id = base_node.id

    del graph.nodes[node_to_merge.id]
    del graph.adjacency[node_to_merge.id]
