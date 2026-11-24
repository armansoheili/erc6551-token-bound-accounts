# erc6551-token-bound-accounts

ERC-6551 token-bound accounts (TBAs) simulator in pure Python — zero dependencies.

A token-bound account is a smart-contract wallet owned by whoever holds a
specific ERC-721 token. The account address is deterministic: the registry
deploys a minimal proxy via CREATE2 with

```
salt = keccak256(abi.encode(chainId, tokenContract, tokenId))
```

so anyone can compute the account for a token before it exists. Selling the
NFT moves control of the account — and everything inside it — to the buyer.

## What's inside

- `erc6551.py` — the whole simulator:
  - **Keccak-256 from scratch** — Keccak-f[1600] sponge, verified against the
    empty-string, `"abc"` and `"hello world"` vectors (cross-checked with
    PyCryptodome).
  - **EIP-55** checksummed addresses and **EIP-1014 CREATE2** address
    derivation.
  - **`ERC721`** — minimal ledger: mint, transfer, `owner_of`.
  - **`Registry`** — `account(...)` predicts the TBA address;
    `create_account(...)` deploys it (one account per token).
  - **`TokenBoundAccount`** — owner-gated `execute()`, `nonce()`, and an
    ERC-1271-style `is_valid_signer()` check; ownership is read live from
    the NFT ledger, so it follows the token when it is sold.

## Run it

```bash
python3 erc6551.py --demo   # mint an NFT, deploy its account, sell the NFT
python3 erc6551.py --test   # 28 doctests
```

Demo output (abridged):

```
predicted: 0xccc42ae9e953E298203348D041b83B985bEa4e74
deployed:  0xccc42ae9e953E298203348D041b83B985bEa4e74
owner:     0xALicE000000000000000000000000000000000001
calls: 1 | nonce: 1
after the NFT sale, owner is now: 0xb0b000000000000000000000000000000000000001
alice can no longer execute: only the token owner may execute
bob executes fine; nonce: 2
```

## Why it matters

Token-bound accounts turn every NFT into a wallet: game items that hold
their own inventory, PFPs with an on-chain asset history, DAOs whose
membership token *is* the treasury signer. The address-prediction trick is
the key — marketplaces and games can show the account (and its contents)
for a token that has never deployed one.
