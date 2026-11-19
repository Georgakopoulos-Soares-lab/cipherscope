# Cover letter — draft

JCEN does not require a cover letter, but the portal gives you a comments box
for the editor. Paste this there, or send it as a related file. Fill in the
bracketed parts.

---

Dear Editors,

We are submitting our manuscript, *CipherScope: Runtime Semantic Observability
and Diagnosis for OpenFHE Programs*, for consideration as a research article in
the Journal of Cryptographic Engineering.

Developers writing FHE applications can see where time is spent but not why.
Whether several rotations read the same ciphertext, whether a generated
evaluation key is ever used, how much of a configured multiplicative-depth
budget a run actually consumes — these decide an encrypted program's cost and
correctness, and a timing profile cannot express any of them. CipherScope
observes an OpenFHE program at its application boundary, through a Python proxy
or a GCC plugin for unmodified C++, and rebuilds the run as a validated graph of
ciphertext versions, state transitions and provenance. Conservative rules over
that graph report candidate optimizations and misconfigurations, each carrying
the evidence that triggered it, and each abstaining with a stated reason when
its preconditions were never observed.

We also measure the observation boundary rather than assuming it away. Every run
receives a coverage class, and only completely observed runs enter our quality
claims.

Across CKKS, BFV and BGV, tracing preserves program output. On a known-answer
benchmark the system recovers all 31 seeded positives with no false positives on
44 hard negatives. On an independently authored workload corpus, six of eight
adjudicated findings were actionable; acting on them gave speedups of up to
4.03×, and also surfaced a measured security–performance trade-off where
enforcing standard security settings made two workloads substantially slower.
Tracing costs under 2% on realistic workloads.

We believe the work fits JCEN's interest in the engineering of cryptographic
systems, and it sits beside prior work in the journal on profiling approximate
homomorphic encryption libraries — HEProfiler (Takeshita et al., JCEN 15(14),
2025), which we discuss in our related work. Where library profilers
characterize the cost of the primitives, CipherScope attributes cost and
correctness to the choices an application makes.

All data, code, raw records, checksums and regeneration commands are openly
available at https://github.com/Georgakopoulos-Soares-lab/cipherscope.

The manuscript is original, is not under consideration elsewhere, and all
authors have approved the submission. We declare no competing interests.

[Optional: suggested reviewers, or reviewers to exclude.]

Thank you for your consideration.

Sincerely,

Kimon Antonios Provatas, on behalf of all authors
The University of Texas at Austin
kap4722@eid.utexas.edu
