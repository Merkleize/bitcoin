This repo is a fork of [bitcoin-inquisition](https://github.com/bitcoin-inquisition/bitcoin) used to develop the opcodes of the [MATT covenant proposal](https://merkle.fun/) for bitcoin.

Active branches:
- [checkcontractverify](https://github.com/Merkleize/bitcoin/tree/checkcontractverify): contains the core `OP_CHECKCONTRACTVERIFY` opcode, and some basic tests.
- [matt](https://github.com/Merkleize/bitcoin/tree/matt): the same as the previous branch, but also activates the `OP_CAT` opcode on taproot Scripts.

Archived branches:
- [matt-vault](https://github.com/Merkleize/bitcoin/tree/matt-vault): a demo of a simple vault construction [posted](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2023-April/021588.html) to the bitcoin-dev mailing list (with an earlier version of the opcodes).
