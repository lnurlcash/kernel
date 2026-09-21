"""Drive Bitcoin Core's OWN BIP341 test vectors through the binding, before any
of this package's own logic is involved. If these pass, the ctypes layer is
wired correctly against the real library; if they fail, nothing built on top
can be trusted.
"""

import json

from lnurlcashkernel import _native


def _vectors(core_data):
    return json.loads((core_data / "bip341_wallet_vectors.json").read_text())


def test_core_signed_taproot_transaction_verifies_on_every_input(core_data):
    vec = _vectors(core_data)["keyPathSpending"][0]
    tx = bytes.fromhex(vec["auxiliary"]["fullySignedTx"])
    spent = [
        (bytes.fromhex(u["scriptPubKey"]), u["amountSats"])
        for u in vec["given"]["utxosSpent"]
    ]
    assert len(spent) == 9
    for i, (script, amount) in enumerate(spent):
        assert _native.verify_input(
            script_pubkey=script,
            amount=amount,
            tx=tx,
            spent_outputs=spent,
            input_index=i,
        ), f"Core's own signed input {i} was rejected"


def test_a_tampered_signature_is_rejected(core_data):
    vec = _vectors(core_data)["keyPathSpending"][0]
    tx = bytearray(bytes.fromhex(vec["auxiliary"]["fullySignedTx"]))
    spent = [
        (bytes.fromhex(u["scriptPubKey"]), u["amountSats"])
        for u in vec["given"]["utxosSpent"]
    ]
    # flip a byte inside the witness region (well past the txin/txout data)
    tx[len(tx) - 40] ^= 0x01
    results = [
        _native.verify_input(
            script_pubkey=s, amount=a, tx=bytes(tx), spent_outputs=spent,
            input_index=i,
        )
        for i, (s, a) in enumerate(spent)
    ]
    assert not all(results), "a corrupted transaction still verified everywhere"


def test_wrong_amount_is_rejected(core_data):
    # BIP341's sighash commits to every spent amount, so lying about one must
    # invalidate the signature - the property that binds a signature to a value
    vec = _vectors(core_data)["keyPathSpending"][0]
    tx = bytes.fromhex(vec["auxiliary"]["fullySignedTx"])
    spent = [
        (bytes.fromhex(u["scriptPubKey"]), u["amountSats"])
        for u in vec["given"]["utxosSpent"]
    ]
    lied = list(spent)
    lied[0] = (lied[0][0], lied[0][1] + 1)
    assert not _native.verify_input(
        script_pubkey=lied[0][0], amount=lied[0][1], tx=tx,
        spent_outputs=lied, input_index=0,
    )
