"""AVL balance index with logarithmic search, insertion, and rotations."""

from collections import deque
from dataclasses import dataclass
from typing import Iterator


@dataclass
class _Node:
    key: int
    value: int
    height: int = 1
    left: "_Node | None" = None
    right: "_Node | None" = None


class AVLTree:
    """Map integer account IDs to balance cents while maintaining AVL height."""

    def __init__(self) -> None:
        self._root: _Node | None = None
        self._size = 0

    @staticmethod
    def _height(node: _Node | None) -> int:
        return node.height if node else 0

    @classmethod
    def _update_height(cls, node: _Node) -> None:
        node.height = 1 + max(cls._height(node.left), cls._height(node.right))

    @classmethod
    def _balance_factor(cls, node: _Node) -> int:
        return cls._height(node.left) - cls._height(node.right)

    @classmethod
    def _rotate_right(cls, root: _Node) -> _Node:
        pivot = root.left
        if pivot is None:
            return root
        root.left = pivot.right
        pivot.right = root
        cls._update_height(root)
        cls._update_height(pivot)
        return pivot

    @classmethod
    def _rotate_left(cls, root: _Node) -> _Node:
        pivot = root.right
        if pivot is None:
            return root
        root.right = pivot.left
        pivot.left = root
        cls._update_height(root)
        cls._update_height(pivot)
        return pivot

    @classmethod
    def _rebalance(cls, node: _Node) -> _Node:
        cls._update_height(node)
        balance = cls._balance_factor(node)
        if balance > 1:
            if node.left and cls._balance_factor(node.left) < 0:
                node.left = cls._rotate_left(node.left)
            return cls._rotate_right(node)
        if balance < -1:
            if node.right and cls._balance_factor(node.right) > 0:
                node.right = cls._rotate_right(node.right)
            return cls._rotate_left(node)
        return node

    def insert(self, key: int, value: int) -> None:
        """Insert or update a key in O(log N) time."""
        existed = self.search(key) is not None

        def add(node: _Node | None) -> _Node:
            if node is None:
                return _Node(key, value)
            if key < node.key:
                node.left = add(node.left)
            elif key > node.key:
                node.right = add(node.right)
            else:
                node.value = value
                return node
            return self._rebalance(node)

        self._root = add(self._root)
        if not existed:
            self._size += 1

    def search(self, key: int) -> int | None:
        """Return the value for ``key`` in O(log N) time, or ``None``."""
        node = self._root
        while node:
            if key == node.key:
                return node.value
            node = node.left if key < node.key else node.right
        return None

    def inorder(self) -> Iterator[tuple[int, int]]:
        """Yield key/value pairs in sorted key order."""
        stack: list[_Node] = []
        node = self._root
        while stack or node:
            while node:
                stack.append(node)
                node = node.left
            node = stack.pop()
            yield node.key, node.value
            node = node.right

    def shape(self, max_depth: int = 3) -> dict[str, list[dict[str, object]]]:
        """Return an anonymized tree shape without account IDs or balance values."""
        if self._root is None:
            return {"nodes": [], "edges": []}
        nodes: list[dict[str, object]] = []
        edges: list[dict[str, str]] = []
        queue = deque([(self._root, "n0", 0, 0)])
        next_id = 1
        while queue:
            node, node_id, depth, position = queue.popleft()
            nodes.append(
                {"id": node_id, "depth": depth, "position": position}
            )
            if depth >= max_depth:
                continue
            for child, child_position in (
                (node.left, position * 2),
                (node.right, position * 2 + 1),
            ):
                if child is None:
                    continue
                child_id = f"n{next_id}"
                next_id += 1
                edges.append({"source": node_id, "target": child_id})
                queue.append((child, child_id, depth + 1, child_position))
        return {"nodes": nodes, "edges": edges}

    @property
    def height(self) -> int:
        """Return the current tree height."""
        return self._height(self._root)

    @property
    def size(self) -> int:
        """Return the number of distinct keys."""
        return self._size
