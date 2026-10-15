# Privacy token anonymity model

Privacy tokens (ZY / Zyphora outputs) hide the *value* and *identity* of what
is transacted, but not the *fact* that a transaction uses tokens. Read this
before relying on token transactions for metadata privacy.

## What is hidden

| Property | How |
| --- | --- |
| Output amount | Pedersen commitment `C = amount*T + mask*G`; the amount is never on-chain in the clear. |
| Token identity | The token id is blinded per output: `T = token_id + r*X`. The numeric id is not revealed. |
| Which ring member is spent | A token spend (`txin_zy_input`) references a ring of `key_offsets`; the real spent output is hidden among the ring members, exactly as with native spends. |

## What is NOT hidden

| Property | Why |
| --- | --- |
| That a transaction is a token transaction | Token inputs and outputs use distinct variant tags (`zy_input`, `zyphora`) and, for lifecycle operations, distinct tx types (`update_token`, `burn_token`). Any observer parsing the chain can tell a token tx from a native one. |
| The number of token inputs and outputs | Each input/output self-identifies by variant tag, so counts are directly observable. |
| The token-vs-native split | For a mixed transaction, how many outputs are token outputs versus native outputs is visible. |

## Type anonymity within a transaction

A confidential-asset transfer proves each output's token type equals one of the
transaction's *input* token types (an asset surjection proof). The anonymity set
for an output's type is therefore the set of distinct input token types in that
same transaction.

For a typical transfer with a single token input, that set has size one: an
observer cannot read the blinded token id, but there is only one candidate type,
so within-transaction token-type privacy rests on the blinding alone, not on a
decoy set. This is a deliberate property of the confidential-asset design, not a
defect. It is distinct from ring (mixin) anonymity, which still hides *which*
output is being spent.

## Practical guidance

- Treat the presence, count, and native split of token activity as public.
- Do not assume the *kind* of token activity is unlinkable within a single
  transaction when it has only one token input.
- Amounts and token ids remain confidential in all cases above.
