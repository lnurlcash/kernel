"""ctypes binding to Bitcoin Core's `libbitcoinkernel`.

Deliberately thin: it exposes exactly the calls needed to ask Core "does this
input spend that script pubkey?" and nothing else. No verification logic lives
here or anywhere else in this package - the answer always comes from Core's own
interpreter, compiled unmodified from the pinned `vendor/bitcoin` tree.

stdlib ctypes rather than cffi/pybind: a security-sensitive package should not
grow a compiled binding layer of its own to audit.
"""

from __future__ import annotations

import ctypes
import functools
import os
import sys
from pathlib import Path

from .errors import KernelError

# btck_ScriptVerificationFlags (src/kernel/bitcoinkernel.h). Only the flags this
# package ever passes are named; ALL is the consensus set incl. TAPROOT.
FLAG_P2SH = 1 << 0
FLAG_DERSIG = 1 << 2
FLAG_NULLDUMMY = 1 << 4
FLAG_CHECKLOCKTIMEVERIFY = 1 << 9
FLAG_CHECKSEQUENCEVERIFY = 1 << 10
FLAG_WITNESS = 1 << 11
FLAG_TAPROOT = 1 << 17
FLAGS_ALL = (
    FLAG_P2SH
    | FLAG_DERSIG
    | FLAG_NULLDUMMY
    | FLAG_CHECKLOCKTIMEVERIFY
    | FLAG_CHECKSEQUENCEVERIFY
    | FLAG_WITNESS
    | FLAG_TAPROOT
)

# btck_ScriptVerifyStatus
STATUS_OK = 0

_LIB_NAMES = {
    "linux": "libbitcoinkernel.so",
    "darwin": "libbitcoinkernel.dylib",
    "win32": "bitcoinkernel.dll",
}


def _library_path() -> Path:
    override = os.environ.get("LNURLCASHKERNEL_LIB")
    if override:
        return Path(override)
    name = _LIB_NAMES.get(sys.platform, "libbitcoinkernel.so")
    bundled = Path(__file__).parent / "_lib" / name
    if bundled.exists():
        return bundled
    raise KernelError(
        f"libbitcoinkernel not found (looked for {bundled}). Install a built "
        "wheel, or set LNURLCASHKERNEL_LIB to a dev build."
    )


@functools.lru_cache(maxsize=1)
def _lib() -> ctypes.CDLL:
    try:
        lib = ctypes.CDLL(str(_library_path()))
    except OSError as err:
        raise KernelError(f"could not load libbitcoinkernel: {err}") from err

    vp, sz = ctypes.c_void_p, ctypes.c_size_t
    sigs = {
        "btck_script_pubkey_create": ([vp, sz], vp),
        "btck_script_pubkey_destroy": ([vp], None),
        "btck_transaction_create": ([vp, sz], vp),
        "btck_transaction_destroy": ([vp], None),
        "btck_transaction_output_create": ([vp, ctypes.c_int64], vp),
        "btck_transaction_output_destroy": ([vp], None),
        "btck_precomputed_transaction_data_create": (
            [vp, ctypes.POINTER(vp), sz],
            vp,
        ),
        "btck_precomputed_transaction_data_destroy": ([vp], None),
        "btck_script_pubkey_verify": (
            [
                vp,
                ctypes.c_int64,
                vp,
                vp,
                ctypes.c_uint,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint8),
            ],
            ctypes.c_int,
        ),
    }
    for name, (argtypes, restype) in sigs.items():
        try:
            fn = getattr(lib, name)
        except AttributeError as err:
            raise KernelError(
                f"{name} missing from libbitcoinkernel - wrong Core version?"
            ) from err
        fn.argtypes = argtypes
        fn.restype = restype
    return lib


class _Owned:
    """Frees a native handle exactly once, even if verification raises."""

    __slots__ = ("ptr", "_destroy")

    def __init__(self, ptr: int | None, destroy_name: str, what: str) -> None:
        if not ptr:
            raise KernelError(f"libbitcoinkernel rejected the {what}")
        self.ptr = ptr
        self._destroy = getattr(_lib(), destroy_name)

    def close(self) -> None:
        if self.ptr:
            self._destroy(self.ptr)
            self.ptr = None


def verify_input(
    *,
    script_pubkey: bytes,
    amount: int,
    tx: bytes,
    spent_outputs: list[tuple[bytes, int]],
    input_index: int,
    flags: int = FLAGS_ALL,
) -> bool:
    """Ask Core whether input `input_index` of the serialized `tx` spends
    `script_pubkey`.

    `spent_outputs` is (script_pubkey, amount) for EVERY input of `tx`, in
    order - BIP341's sighash commits to all of them, so a taproot verify is
    impossible without the full set.

    Returns Core's verdict. Raises KernelError only if the call itself could not
    be made (bad handle, invalid flag combination) - never for "script false".
    """
    lib = _lib()
    owned: list[_Owned] = []
    try:
        spk = _Owned(
            lib.btck_script_pubkey_create(script_pubkey, len(script_pubkey)),
            "btck_script_pubkey_destroy",
            "script pubkey",
        )
        owned.append(spk)
        tx_h = _Owned(
            lib.btck_transaction_create(tx, len(tx)),
            "btck_transaction_destroy",
            "transaction",
        )
        owned.append(tx_h)

        out_ptrs = []
        for out_script, out_amount in spent_outputs:
            out_spk = _Owned(
                lib.btck_script_pubkey_create(out_script, len(out_script)),
                "btck_script_pubkey_destroy",
                "spent output script",
            )
            owned.append(out_spk)
            out = _Owned(
                lib.btck_transaction_output_create(out_spk.ptr, out_amount),
                "btck_transaction_output_destroy",
                "spent output",
            )
            owned.append(out)
            out_ptrs.append(out.ptr)

        arr = (ctypes.c_void_p * len(out_ptrs))(*out_ptrs)
        txdata = _Owned(
            lib.btck_precomputed_transaction_data_create(
                tx_h.ptr, arr, len(out_ptrs)
            ),
            "btck_precomputed_transaction_data_destroy",
            "precomputed transaction data",
        )
        owned.append(txdata)

        status = ctypes.c_uint8(STATUS_OK)
        ok = lib.btck_script_pubkey_verify(
            spk.ptr,
            amount,
            tx_h.ptr,
            txdata.ptr,
            input_index,
            flags,
            ctypes.byref(status),
        )
        if status.value != STATUS_OK:
            raise KernelError(
                f"btck_script_pubkey_verify failed to run (status {status.value})"
            )
        return ok == 1
    finally:
        # reverse order: dependents before what they were built from
        for handle in reversed(owned):
            handle.close()
