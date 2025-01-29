## TODOs

- [x] Test GP TEE implementations or t_cose_crypto_sign() and
  t_cose_crypto_verify() functions
  - signing and verification ok
- [x] Test mbedtls_pk_parse_key() on EC public key PEM
  - mbedtls_ecp_export() on a public key (i.e., no `d`); what would happen?
- [-] Fix `d` and `point` buffer locations. They are now stack-allcoated
  - They are now not stack-allocated, but I am unhappy with current `d` and
    `point` buffer locations...
- [ ] COSE_Sign1 tests
  - [ ] Create TBS hash
  - [ ] Sign TBS hash and output a COSE_Sign1 object
  - [ ] Re-coustruct TBS hash from given COSE_Sign1 object
  - [ ] Signature verification test
- [ ] Support different algorithm(s)
  - [ ] ES384
  - [ ] EdDSA