"""Resource discovery graph for unified asset tracking"""

from collections import defaultdict
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, List, Set, Any


class ResourceType(Enum):
    """Asset resource types in the discovery graph"""
    ACCOUNT = "account"
    COOKIE = "cookie"
    ENDPOINT = "endpoint"
    FILE = "file"
    HEADER = "header"
    PORT = "port"
    SUBDOMAIN = "subdomain"


@dataclass
class ResourceNode:
    """Node in the resource graph"""
    node_id: str
    resource_type: ResourceType
    attributes: Dict[str, Any]
    discovered_at: int


@dataclass
class ResourceEdge:
    """Edge in the resource graph"""
    source_id: str
    target_id: str
    relationship: str
    attributes: Dict[str, Any]


class ResourceGraph:
    """Unified resource discovery graph"""
    
    def __init__(self):
        self.nodes: Dict[str, ResourceNode] = {}
        self.edges: List[ResourceEdge] = []
        self.node_index: Dict[ResourceType, Set[str]] = defaultdict(set)
    
    def add_node(self, node: ResourceNode):
        """Add resource node"""
        self.nodes[node.node_id] = node
        self.node_index[node.resource_type].add(node.node_id)
    
    def add_edge(self, edge: ResourceEdge):
        """Add relationship edge"""
        self.edges.append(edge)
    
    def get_nodes_by_type(self, resource_type: ResourceType) -> List[ResourceNode]:
        """Get all nodes of a type"""
        return [self.nodes[nid] for nid in self.node_index[resource_type]]
    
    def to_dict(self) -> Dict:
        """Export graph as dictionary"""
        return {
            'nodes': {nid: asdict(node) for nid, node in self.nodes.items()},
            'edges': [asdict(edge) for edge in self.edges],
            'statistics': {
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'by_type': {
                    rt.value: len(self.node_index[rt])
                    for rt in ResourceType
                }
            }
        }
