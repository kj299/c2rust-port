# Intentional divergences — adler32 port

Places the Rust port deliberately differs from the C reference. Each is a
fix-of-C-defect (the prime directive: the C is a spec that may itself be buggy).

- [x] overflow-10k-a [sha256:f1dff6ae73c9]: the C reference accumulates s1/s2 in uint32_t
  and takes the modulo only at the end, so s2 overflows uint32 on long inputs
  (here 10000 bytes). The Rust port blocks every NMAX=5552 bytes like zlib, so no
  accumulator overflows — it is CORRECT where the C is wrong. Verified: on this
  vector C=0x9edacde3, Rust=0x9fbbcde3 (the reference value).
