"""Keep tapscript's upgrade paths closed.

Any leaf script is accepted and judged by Bitcoin Core's consensus rules - with
one exception consensus itself leaves open. BIP-341/342 reserve two soft-fork
hooks that succeed unconditionally today: an unknown leaf version, and any
OP_SUCCESSx opcode anywhere in a leaf. On-chain, nodes refuse to relay those
(policy flags); libbitcoinkernel only exposes consensus flags, so the same
refusal happens here instead. Without it, such a leaf would be spendable by
anyone who sees it, and no new opcode could ever be given a meaning later.

BIP-342's third hook, a signature check against a key that is neither empty nor
32 bytes, cannot be spotted statically (the key may come from the witness).
It is left to consensus: a wallet must simply never write such keys.
"""

from __future__ import annotations

from .errors import UnsupportedScript
from .taproot import TAPLEAF_VERSION

_TAPLEAF_VERSION_MASK = 0xFE
_OP_PUSHDATA1, _OP_PUSHDATA2, _OP_PUSHDATA4 = 0x4C, 0x4D, 0x4E

# BIP-342: 80, 98, 126-129, 131-134, 137-138, 141-142, 149-153, 187-254
OP_SUCCESS = frozenset(
    [80, 98, *range(126, 130), *range(131, 135), 137, 138, 141, 142,
     *range(149, 154), *range(187, 255)]
)


def _opcodes(script: bytes):
    """The opcodes of `script`, skipping pushed data. Stops at a truncated
    push - Core fails such a script on its own."""
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if 1 <= op <= 75:
            i += op
        elif op == _OP_PUSHDATA1:
            if i + 1 > len(script):
                return
            i += 1 + script[i]
        elif op == _OP_PUSHDATA2:
            if i + 2 > len(script):
                return
            i += 2 + int.from_bytes(script[i : i + 2], "little")
        elif op == _OP_PUSHDATA4:
            if i + 4 > len(script):
                return
            i += 4 + int.from_bytes(script[i : i + 4], "little")
        else:
            yield op


def check_leaf(script: bytes, control_block: bytes) -> None:
    """Raise UnsupportedScript if this leaf uses an upgrade hook."""
    if not control_block or control_block[0] & _TAPLEAF_VERSION_MASK != TAPLEAF_VERSION:
        raise UnsupportedScript("unknown tapleaf version")
    if any(op in OP_SUCCESS for op in _opcodes(script)):
        raise UnsupportedScript("leaf uses a reserved OP_SUCCESS opcode")
