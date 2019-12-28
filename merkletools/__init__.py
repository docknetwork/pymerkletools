import hashlib
from typing import List

try:
    import sha3
except:
    from warnings import warn
    warn("sha3 is not working!")


ACCEPTABLE_HFS = ['sha224', 'sha256', 'sha384', 'sha512',
                  'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
                  'blake2s', 'blake2b',
                  'shake_128', 'shake_256',
                  'keccak_224', 'keccak_256', 'keccak_384', 'keccak_512'
                  ]


class MerkleTools:
    __slots__ = ["hash_type", "hash_function", "leafs", "levels", "is_ready"]

    def __init__(self, hash_type: str) -> None:
        self.hash_type = hash_type.lower()
        assert self.hash_type in ACCEPTABLE_HFS, "hash function {} not supported".format(hash_type)
        if not self.hash_type.startswith("keccak_"):
            self.hash_function = getattr(hashlib, self.hash_type)
        else:
            self.hash_function = getattr(sha3, self.hash_type)

        self.reset_tree()

    def _to_hex(self, x) -> str:
        return x.hex()

    def reset_tree(self) -> None:
        self.leafs = []
        self.levels = None
        self.is_ready = False

    def add_leaf(self, values: List, do_hash: bool = False) -> None:
        self.is_ready = False
        # check if single leaf
        if not isinstance(values, (tuple, list)):
            values = [values]
        for v in values:
            if do_hash:
                v = v.encode('utf-8')
                v = self.hash_function(v).hexdigest()
            v = bytearray.fromhex(v)
            self.leafs.append(v)

    def get_leaf(self, index: int) -> str:
        return self._to_hex(self.leafs[index])

    def get_leaf_count(self) -> int:
        return len(self.leafs)

    def get_tree_ready_state(self) -> bool:
        return self.is_ready

    def _calculate_next_level(self) -> None:
        solo_leaf = None
        N = len(self.levels[0])  # number of leafs on the level
        if N % 2 == 1:  # if odd number of leafs on the level
            solo_leaf = self.levels[0][-1]
            N -= 1

        new_level = []
        for l, r in zip(self.levels[0][0:N:2], self.levels[0][1:N:2]):
            new_level.append(self.hash_function(l + r).digest())
        if solo_leaf is not None:
            new_level.append(solo_leaf)
        self.levels = [new_level, ] + self.levels  # prepend new level

    def make_tree(self) -> None:
        self.is_ready = False
        if self.get_leaf_count() > 0:
            self.levels = [self.leafs, ]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
        self.is_ready = True

    def get_merkle_root(self) -> str:
        if self.is_ready:
            if self.levels is not None:
                return self._to_hex(self.levels[0][0])
        return ""

    def get_proof(self, index: int) -> List:
        if self.levels is None:
            return []
        elif not self.is_ready or index > len(self.leafs) - 1 or index < 0:
            return []
        else:
            proof = []
            for x in range(len(self.levels) - 1, 0, -1):
                level_len = len(self.levels[x])
                if (index == level_len - 1) and (level_len % 2 == 1):  # skip if this is an odd end node
                    index = int(index / 2.)
                    continue
                is_right_node = index % 2
                sibling_index = index - 1 if is_right_node else index + 1
                sibling_pos = "left" if is_right_node else "right"
                sibling_value = self._to_hex(self.levels[x][sibling_index])
                proof.append({sibling_pos: sibling_value})
                index = int(index / 2.)
            return proof

    def validate_proof(self, proof, target_hash, merkle_root) -> bool:
        merkle_root = bytearray.fromhex(merkle_root)
        target_hash = bytearray.fromhex(target_hash)
        if len(proof) == 0:
            return target_hash == merkle_root
        else:
            proof_hash = target_hash
            for p in proof:
                try:
                    # the sibling is a left node
                    sibling = bytearray.fromhex(p['left'])
                    proof_hash = self.hash_function(sibling + proof_hash).digest()
                except:
                    # the sibling is a right node
                    sibling = bytearray.fromhex(p['right'])
                    proof_hash = self.hash_function(proof_hash + sibling).digest()
            return proof_hash == merkle_root
