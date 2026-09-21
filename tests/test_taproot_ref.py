"""Pin the test-only reference code to Bitcoin Core's own BIP341 vectors, so the
spends later tests build are trustworthy inputs rather than a second unverified
implementation checking the first."""

import json

import taproot_ref as t


def _vectors(core_data):
    return json.loads((core_data / "bip341_wallet_vectors.json").read_text())


def test_output_key_derivation_matches_core_vectors(core_data):
    for v in _vectors(core_data)["scriptPubKey"]:
        internal = bytes.fromhex(v["given"]["internalPubkey"])
        tree = v["given"]["scriptTree"]
        root = bytes.fromhex(v["intermediary"]["merkleRoot"]) if tree else b""
        q, _ = t.tweak_output_key(internal, root)
        assert t.p2tr_script(q).hex() == v["expected"]["scriptPubKey"]


def test_keypath_sighash_matches_core_vectors(core_data):
    vec = _vectors(core_data)["keyPathSpending"][0]
    raw = bytes.fromhex(vec["given"]["rawUnsignedTx"])
    spent = vec["given"]["utxosSpent"]
    version = int.from_bytes(raw[0:4], "little", signed=True)
    pos = 4
    n_in = raw[pos]
    pos += 1
    prevouts, sequences = [], []
    for _ in range(n_in):
        txid = raw[pos : pos + 32]
        vout = int.from_bytes(raw[pos + 32 : pos + 36], "little")
        assert raw[pos + 36] == 0  # empty scriptSig in the unsigned tx
        seq = int.from_bytes(raw[pos + 37 : pos + 41], "little")
        prevouts.append((txid, vout))
        sequences.append(seq)
        pos += 41
    n_out = raw[pos]
    pos += 1
    outputs = []
    for _ in range(n_out):
        value = int.from_bytes(raw[pos : pos + 8], "little", signed=True)
        slen = raw[pos + 8]
        outputs.append((value, raw[pos + 9 : pos + 9 + slen]))
        pos += 9 + slen
    locktime = int.from_bytes(raw[pos : pos + 4], "little")

    checked = 0
    for inp in vec["inputSpending"]:
        # this reference implements SIGHASH_DEFAULT/ALL only
        if inp["given"]["hashType"] not in (0, 1):
            continue
        got = t.tapscript_sighash(
            version=version,
            locktime=locktime,
            prevouts=prevouts,
            amounts=[u["amountSats"] for u in spent],
            spent_scripts=[bytes.fromhex(u["scriptPubKey"]) for u in spent],
            sequences=sequences,
            outputs=outputs,
            input_index=inp["given"]["txinIndex"],
            leaf_hash=None,
            hash_type=inp["given"]["hashType"],
        )
        assert got.hex() == inp["intermediary"]["sigHash"]
        checked += 1
    assert checked >= 1


def test_schnorr_sign_roundtrips_through_the_real_verifier():
    # BIP340 vector 0 from the spec: seckey 3, aux 0, msg 0
    sig = t.schnorr_sign(b"\x00" * 32, (3).to_bytes(32, "big"))
    assert sig.hex().upper() == (
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    )
