"""
blockchain.py
-------------
A minimal, dependency-free blockchain implementation used to record
DDoS detection events and mitigation actions in a tamper-evident,
append-only ledger.

This stands in for a full Ethereum/Solidity deployment (which would
need Ganache/Node tooling and network access) while preserving the
core properties this project relies on:

  - Each block is cryptographically linked to the previous one (hash chain)
  - Proof-of-work makes retroactively altering a block computationally
    expensive, simulating blockchain immutability
  - The chain can be validated at any time to detect tampering
  - Multiple "nodes" (see node.py) can hold independent copies of the
    chain and reach consensus via a longest-valid-chain rule, simulating
    the decentralization a real multi-node deployment would provide

To point this at a real Ethereum network instead, swap this module for
a Web3.py client that calls an equivalent Solidity smart contract
(see smart_contract.sol for a reference contract with the same fields).
"""
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Block:
    index: int
    timestamp: float
    data: Dict[str, Any]
    previous_hash: str
    nonce: int = 0
    hash: str = field(default="", repr=False)

    def compute_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
        }


class Blockchain:
    DIFFICULTY = 3  # number of leading zeros required in a valid hash

    def __init__(self):
        self.chain: List[Block] = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(index=0, timestamp=time.time(),
                         data={"type": "genesis", "message": "DDoS defense ledger initialized"},
                         previous_hash="0")
        genesis.hash = self._proof_of_work(genesis)
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def _proof_of_work(self, block: Block) -> str:
        block.nonce = 0
        computed = block.compute_hash()
        target = "0" * self.DIFFICULTY
        while not computed.startswith(target):
            block.nonce += 1
            computed = block.compute_hash()
        return computed

    def add_block(self, data: Dict[str, Any]) -> Block:
        new_block = Block(
            index=self.last_block.index + 1,
            timestamp=time.time(),
            data=data,
            previous_hash=self.last_block.hash,
        )
        new_block.hash = self._proof_of_work(new_block)
        self.chain.append(new_block)
        return new_block

    def is_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current, prev = self.chain[i], self.chain[i - 1]
            if current.previous_hash != prev.hash:
                return False
            if current.hash != current.compute_hash():
                return False
            if not current.hash.startswith("0" * self.DIFFICULTY):
                return False
        return True

    def to_list(self) -> List[Dict[str, Any]]:
        return [b.to_dict() for b in self.chain]

    def reset(self):
        """Reinitialize to a fresh genesis block, in place -- so any
        other module holding a reference to this same Blockchain
        instance (e.g. protected_site.py) sees the reset too, rather
        than continuing to use a stale pre-reset chain."""
        self.chain = []
        self._create_genesis_block()
