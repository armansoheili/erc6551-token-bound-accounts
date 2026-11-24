"""ERC-6551 token-bound accounts simulator in pure Python.

A token-bound account (TBA) is a smart-contract wallet whose owner is the
holder of a specific ERC-721 token.  The account address is deterministic:
the ERC-6551 registry deploys a minimal proxy via CREATE2 with

    salt = keccak256(abi.encode(chainId, tokenContract, tokenId))

so anyone can compute the account address for a token before it exists.

This module is a self-contained simulation (no network, no dependencies):
a tiny ERC-721 ledger, the registry, and the account contract with
owner-gated execution.  The Keccak-256 sponge below is a from-scratch
implementation of the Keccak-f[1600] permutation, verified against the
well-known empty-string and "abc" test vectors.
"""

from __future__ import annotations

import argparse
import doctest

__all__ = [
    "keccak256",
    "checksum_address",
    "create2_address",
    "ERC721",
    "Registry",
    "TokenBoundAccount",
]

# ---------------------------------------------------------------------------
# Keccak-256 (Keccak-f[1600], rate 1088 bits / 136 bytes, suffix 0x01)
# ---------------------------------------------------------------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets r[x][y] and pi lane permutation, per the Keccak spec.
_R = [[0, 36, 3, 41, 18],
      [1, 44, 10, 45, 2],
      [62, 6, 43, 15, 61],
      [28, 55, 25, 21, 56],
      [27, 20, 39, 8, 14]]

_MASK64 = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64 if n else x


def _keccak_f1600(state: list[int]) -> None:
    for rc in _RC:
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # Rho and Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _R[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y])
        # Iota
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Keccak-256 digest of ``data``.

    >>> keccak256(b"").hex()
    'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    >>> keccak256(b"abc").hex()
    '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    >>> keccak256(b"hello world").hex()
    '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad'
    """
    rate = 136
    state = [0] * 25
    # Absorb full blocks.
    for off in range(0, len(data) - len(data) % rate, rate):
        block = data[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f1600(state)
    # Final block with pad10*1, domain suffix 0x01.
    tail = bytearray(data[len(data) - len(data) % rate:])
    tail.append(0x01)
    while len(tail) % rate != rate - 1:
        tail.append(0x00)
    tail.append(0x80)
    for i in range(rate // 8):
        state[i] ^= int.from_bytes(bytes(tail[8 * i:8 * i + 8]), "little")
    _keccak_f1600(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def checksum_address(addr: str) -> str:
    """EIP-55 mixed-case checksum of a 20-byte hex address.

    >>> checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'
    >>> checksum_address("0x0000000000000000000000000000000000000000")
    '0x0000000000000000000000000000000000000000'
    """
    raw = addr.lower().removeprefix("0x")
    digest = keccak256(raw.encode()).hex()
    out = "".join(c.upper() if int(digest[i], 16) >= 8 else c
                  for i, c in enumerate(raw))
    return "0x" + out


def create2_address(deployer: str, salt: bytes, init_code_hash: bytes) -> str:
    """EIP-1014 CREATE2 address: keccak256(0xff || deployer || salt || hash).

    >>> create2_address("0x0000000000000000000000000000000000000000", b"\\x00" * 32, keccak256(b""))
    '0xE33C0C7F7df4809055C3ebA6c09CFe4BaF1BD9e0'
    """
    payload = b"\xff" + bytes.fromhex(deployer.removeprefix("0x")) + salt + init_code_hash
    return checksum_address("0x" + keccak256(payload)[12:].hex())


# ---------------------------------------------------------------------------
# Minimal ERC-721 ledger (only what a TBA needs: ownership of a token id)
# ---------------------------------------------------------------------------

class ERC721:
    """Tiny ERC-721 ledger: mint, transfer, owner_of.

    >>> nft = ERC721("0xC0FFEE000000000000000000000000000000000001")
    >>> nft.mint("0xAlice000000000000000000000000000000000001", 7)
    >>> nft.owner_of(7)
    '0xALicE000000000000000000000000000000000001'
    >>> nft.owner_of(99)
    Traceback (most recent call last):
    ...
    KeyError: 'token 99 does not exist'
    """

    def __init__(self, address: str):
        self.address = checksum_address(address)
        self._owners: dict[int, str] = {}

    def mint(self, to: str, token_id: int) -> None:
        if token_id in self._owners:
            raise ValueError(f"token {token_id} already exists")
        self._owners[token_id] = checksum_address(to)

    def transfer(self, frm: str, to: str, token_id: int) -> None:
        if self.owner_of(token_id) != checksum_address(frm):
            raise ValueError("transfer from incorrect owner")
        self._owners[token_id] = checksum_address(to)

    def owner_of(self, token_id: int) -> str:
        if token_id not in self._owners:
            raise KeyError(f"token {token_id} does not exist")
        return self._owners[token_id]

    def exists(self, token_id: int) -> bool:
        return token_id in self._owners


# ---------------------------------------------------------------------------
# ERC-6551 registry + token-bound account
# ---------------------------------------------------------------------------

# Placeholder ERC-6551 proxy creation code (the real bytecode is the
# ERC-1167 minimal proxy with the implementation + context baked in).
_PROXY_INIT_CODE = bytes.fromhex("3d60ad80600a3d3981f3363d3d373d3d3d363d73") + \
    b"\x00" * 20 + bytes.fromhex("5af43d82803e903d91602b57fd5bf3")


class TokenBoundAccount:
    """A wallet owned by whoever holds one specific ERC-721 token.

    Ownership is read live from the NFT ledger, so selling the token moves
    control of the account (and everything inside it) to the buyer.

    >>> nft = ERC721("0xC0FFEE000000000000000000000000000000000001")
    >>> nft.mint("0xAlice000000000000000000000000000000000001", 7)
    >>> acc = TokenBoundAccount(1, nft, 7, "0xACc000000000000000000000000000000000000001")
    >>> acc.owner()
    '0xALicE000000000000000000000000000000000001'
    >>> acc.execute("0xAlice000000000000000000000000000000000001", "0xB0b000000000000000000000000000000000000001", 0, b"")
    (0, True)
    >>> acc.nonce()
    1
    """

    def __init__(self, chain_id: int, nft: ERC721, token_id: int, address: str):
        self.chain_id = chain_id
        self.nft = nft
        self.token_id = token_id
        self.address = checksum_address(address)
        self._nonce = 0
        self.calls: list[dict] = []

    def owner(self) -> str:
        """Current owner = current holder of the bound token."""
        return self.nft.owner_of(self.token_id)

    def nonce(self) -> int:
        return self._nonce

    def is_valid_signer(self, signer: str, _hash: bytes) -> bool:
        """ERC-1271 style check: only the token owner may sign for the account."""
        return checksum_address(signer) == self.owner()

    def execute(self, caller: str, to: str, value: int, data: bytes) -> tuple[int, bool]:
        """Owner-only call. Returns (nonce used, success); records the call.

        >>> nft = ERC721("0xC0FFEE000000000000000000000000000000000001")
        >>> nft.mint("0xAlice000000000000000000000000000000000001", 7)
        >>> acc = TokenBoundAccount(1, nft, 7, "0xACc000000000000000000000000000000000000001")
        >>> acc.execute("0xB0b000000000000000000000000000000000000001", "0xB0b000000000000000000000000000000000000001", 0, b"")
        Traceback (most recent call last):
        ...
        PermissionError: only the token owner may execute
        """
        if checksum_address(caller) != self.owner():
            raise PermissionError("only the token owner may execute")
        if value < 0:
            raise ValueError("value must be non-negative")
        self.calls.append({"to": checksum_address(to), "value": value, "data": data})
        self._nonce += 1
        return self._nonce - 1, True


class Registry:
    """ERC-6551 registry: deterministic account creation + lookup.

    The account address depends only on (chainId, tokenContract, tokenId,
    implementation, salt), so it can be predicted before deployment.
    """

    def __init__(self, address: str = "0x000000006551c19487814612e58FE06813775758"):
        self.address = checksum_address(address)
        self._accounts: dict[str, TokenBoundAccount] = {}

    @staticmethod
    def _salt(chain_id: int, token_contract: str, token_id: int) -> bytes:
        payload = (chain_id.to_bytes(32, "big")
                   + bytes.fromhex(token_contract.removeprefix("0x"))
                   + token_id.to_bytes(32, "big"))
        return keccak256(payload)

    def account(self, implementation: str, chain_id: int, token_contract: str,
                token_id: int, salt: int = 0) -> str:
        """Predict the account address without deploying it.

        >>> reg = Registry()
        >>> reg.account("0x0000000000000000000000000000000000000001", 1, "0xC0FFEE000000000000000000000000000000000001", 7)
        '0xccc42ae9e953E298203348D041b83B985bEa4e74'
        """
        init_code = _PROXY_INIT_CODE[:-20] + bytes.fromhex(implementation.removeprefix("0x")) \
            + _PROXY_INIT_CODE[-20:]
        # ERC-6551 salt mixes the caller-supplied salt with the token tuple.
        full_salt = keccak256(self._salt(chain_id, token_contract, token_id)
                              + salt.to_bytes(32, "big"))
        return create2_address(self.address, full_salt, keccak256(init_code))

    def create_account(self, implementation: str, chain_id: int, nft: ERC721,
                       token_id: int, salt: int = 0) -> TokenBoundAccount:
        """Deploy (simulate) the account for ``token_id`` and return it.

        >>> nft = ERC721("0xC0FFEE000000000000000000000000000000000001")
        >>> nft.mint("0xAlice000000000000000000000000000000000001", 7)
        >>> reg = Registry()
        >>> acc = reg.create_account("0x0000000000000000000000000000000000000001", 1, nft, 7)
        >>> acc.address == reg.account("0x0000000000000000000000000000000000000001", 1, nft.address, 7)
        True
        >>> reg.create_account("0x0000000000000000000000000000000000000001", 1, nft, 7)
        Traceback (most recent call last):
        ...
        ValueError: account already exists for this token
        """
        addr = self.account(implementation, chain_id, nft.address, token_id, salt)
        if addr in self._accounts:
            raise ValueError("account already exists for this token")
        acc = TokenBoundAccount(chain_id, nft, token_id, addr)
        self._accounts[addr] = acc
        return acc

    def get_account(self, address: str) -> TokenBoundAccount | None:
        return self._accounts.get(checksum_address(address))


def _demo() -> None:
    alice = "0xAlice000000000000000000000000000000000001"
    bob = "0xB0b000000000000000000000000000000000000001"
    nft = ERC721("0xC0FFEE000000000000000000000000000000000001")
    nft.mint(alice, 7)
    reg = Registry()
    impl = "0x0000000000000000000000000000000000000001"
    print("predicted:", reg.account(impl, 1, nft.address, 7))
    acc = reg.create_account(impl, 1, nft, 7)
    print("deployed: ", acc.address)
    print("owner:    ", acc.owner())
    acc.execute(alice, bob, 0, b"hello")
    print("calls:", len(acc.calls), "| nonce:", acc.nonce())
    nft.transfer(alice, bob, 7)
    print("after the NFT sale, owner is now:", acc.owner())
    try:
        acc.execute(alice, bob, 0, b"")
    except PermissionError as exc:
        print("alice can no longer execute:", exc)
    acc.execute(bob, alice, 0, b"")
    print("bob executes fine; nonce:", acc.nonce())


def main() -> None:
    parser = argparse.ArgumentParser(description="ERC-6551 token-bound accounts simulator")
    parser.add_argument("--demo", action="store_true", help="run the demo scenario")
    parser.add_argument("--test", action="store_true", help="run doctests")
    args = parser.parse_args()
    if args.test:
        results = doctest.testmod(verbose=False)
        print(f"{results.attempted} doctests, {results.failed} failed")
        raise SystemExit(1 if results.failed else 0)
    _demo()


if __name__ == "__main__":
    main()
