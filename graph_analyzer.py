"""Directed access-pattern graph with breadth-first and depth-first scans."""

from collections import defaultdict, deque
from collections.abc import Iterable


SUSPICIOUS_SEQUENCE = ("Login", "Database", "Admin", "Files")
SUSPICIOUS_SEQUENCES = (
    SUSPICIOUS_SEQUENCE,
    ("Login", "Database", "Admin denied"),
)


class AccessGraph:
    """Small directed graph for analyzing ordered access events."""

    def __init__(self) -> None:
        self._edges: dict[str, set[str]] = defaultdict(set)

    def add_edge(self, source: str, destination: str) -> None:
        """Add a directed edge between two named event categories."""
        self._edges[source].add(destination)
        self._edges.setdefault(destination, set())

    @classmethod
    def from_sequence(cls, events: Iterable[str]) -> "AccessGraph":
        """Construct a graph from consecutive events in an access history."""
        graph = cls()
        sequence = list(events)
        for source, destination in zip(sequence, sequence[1:]):
            graph.add_edge(source, destination)
        return graph

    def bfs(self, start: str) -> list[str]:
        """Return nodes reachable from ``start`` in breadth-first order."""
        visited: set[str] = set()
        order: list[str] = []
        queue = deque([start])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            order.append(node)
            queue.extend(sorted(self._edges.get(node, set()) - visited))
        return order

    def dfs(self, start: str) -> list[str]:
        """Return nodes reachable from ``start`` in depth-first order."""
        visited: set[str] = set()
        order: list[str] = []
        stack = [start]
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            order.append(node)
            stack.extend(sorted(self._edges.get(node, set()) - visited, reverse=True))
        return order

    def contains_sequence(self, sequence: Iterable[str]) -> bool:
        """Check whether each adjacent pair in a requested path is graph-reachable."""
        path = list(sequence)
        if len(path) < 2:
            return bool(path)
        return all(
            destination in self.bfs(source)
            for source, destination in zip(path, path[1:])
        )

    def suspicious_paths(self) -> list[list[str]]:
        """Return modeled suspicious paths whose graph transitions are present."""
        return [
            list(sequence)
            for sequence in SUSPICIOUS_SEQUENCES
            if self.contains_sequence(sequence)
        ]

    def summary(self, start: str = "Login") -> dict[str, object]:
        """Provide safe traversal data for the current user's monitor page."""
        return {
            "nodes": sorted(self._edges),
            "edges": [
                [source, destination]
                for source in sorted(self._edges)
                for destination in sorted(self._edges[source])
            ],
            "bfs": self.bfs(start),
            "dfs": self.dfs(start),
            "suspicious_paths": self.suspicious_paths(),
        }
