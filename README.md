MFOC is an open source implementation of "offline nested" attack by Nethemba.

This program allow to recover authentication keys from MIFARE Classic card.

---

`mfoc-backdoor` implements the *Faster Backdoored Nested Attack* in Section XI of https://eprint.iacr.org/2024/1275

It can recover keys from cards featuring static encrypted nonces with known backdoor keys (most notably FM11RF08S). It is card-only and does not implement reused keys (Section V) or distance based attacks (Section IX).

Unlike the [Proxmark3 version](https://github.com/RfidResearchGroup/proxmark3/blob/master/client/pyscripts/fm11rf08s_recovery.py), this tool will not search for duplicates between sectors or test keys. To collect nested nonces for supply-chain attacks (Section XIII) or other use see `mf_nested_auth`

Initial testing on a ACR122U / Intel Core i5-6200U @ 2.30GHz, a full card recovery of FM11RF08S with 32 random keys (see [src/example.txt](src/example.txt)) took 2 hours, 54 minutes, 53 seconds.

With ~130000 filtered candidates ACR122 + libnfc averages ≈12.4 attempts/sec, almost 12x slower than a Proxmark3 Easy.

# Build from source

```
autoreconf -is
./configure
make && sudo make install
```

# Usage #
Put one MIFARE Classic tag that you want keys recovering;
Lauching mfoc, you will need to pass options, see
```
mfoc-backdoor -h
```
