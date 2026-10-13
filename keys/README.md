# Signing keys (public halves only)

These keys are TRANSITIONAL: generated on-lane pending the
owner-device ceremony. Every record they sign is LEGACY and
will be re-sealed when the ceremony key arms. Private halves
never live in any repository (README.md, standing law).

- lane key (white-ledger signer): fingerprint a271-8e62-3bff-02d2
- owner key (Unity ID, transitional): fingerprint 9037-6638-6643-83b6
- dual-pipe pole keys (`pipe-v.pub`, `pipe-a.pub`): the verification
  layer's two poles, which co-sign the kernel chain's checkpoints
  (see `kernel/`). Prototype regime from `~/workspace/dual-pipe/`;
  private halves live in the dual-pipe vault, never in any repo.
