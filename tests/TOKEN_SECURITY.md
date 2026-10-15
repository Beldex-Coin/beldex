# Token security regressions

Configure with `-DBUILD_TESTS=ON`, build `unit_tests`, then run:

```sh
ctest --test-dir build -R '^token_security$' --output-on-failure
python3 tests/data/check_token_bge_vector.py tests/data/token_bge_v1.txt
python3 tests/data/check_token_bge_vector.py tests/data/token_bge_legacy.txt --legacy
```

The GitHub Actions `Token security regressions` workflow runs these commands
on pushes and pull requests. The C++ cases also run in the full unit suite.

| Fix | Regression coverage |
| --- | --- |
| `1b99cce` | All 12 cross-typed operation pairs at state and proof validation; valid matching operations; duplicate descriptors; burn requiring a token input; emission commitments matching outputs. |
| `f9fad1f` | Add the scalar order without reducing to every response/challenge field of every proof family; reject both in memory and during deserialization; scalar boundary encodings; malformed points return false without escaping exceptions. |
| `d3c9773` | Frozen current and legacy BGE transcripts; reject a retargeted legacy proof; mutate statement and commitment fields; preserve the native commitment following a token output in a mixed transaction. |
| `9b1250b` | Mint duplicate checks by token ID; all 16 ordered same-token operation pairs excluded from one block template, including pool entries restored after detach; different-token controls; repeated template construction. |
| `fca06e0` | Real packed v7 output records converted on reopen; non-RCT records preserved; native/token distributions and amount indices checked across ranges and gaps; reopen, detach, index reuse, and both migration commit boundaries. |

## Fixture boundaries

The token-state fixtures supply valid composition/ownership proofs but isolate
state validation from full spend validation. The pool fixture seeds the existing
input-validation cache through a narrow friend accessor. It exercises the real
pool parser, duplicate check, and template builder without requiring unrelated
ring signatures. It does not test network admission end to end or replace a full
chain exploit reproducer. The original F0 report is needed to confirm that an
exact reproduction matches every precondition of that report.

Migration restart cases recreate the persistent states at the table-creation
and data-conversion commit boundaries. They do not simulate power loss or an
LMDB I/O failure. The v7 fixture contains native outputs only, as required by
the migration's pre-token-chain assumption.

## BGE vector provenance

Both fixtures use context 123 (32-byte little endian), ring entries `(i+1)*H`
for `i=0..4`, real index 4, and blinding scalar 7. Proof randomness was generated
once and frozen. The positive fixture uses the current prover. The negative
fixture was generated with only the pre-`d3c9773` transcript restored: no domain
tag and no target point in the challenge. It verifies under that old verifier.

`check_token_bge_vector.py` uses independent Python integer arithmetic and a
Keccak-f implementation to check the expected reduced challenge and the BGE
ring equation. It does not call the C++ proof/hash implementation and does not
claim to independently check the generator-commitment equation. The C++ tests
verify the complete positive proof and reject the legacy and retargeted proofs.
The Python script needs no third-party packages.
