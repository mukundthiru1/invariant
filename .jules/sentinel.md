## 2026-03-07 - Missing Bounds Check on PoW Challenge Difficulty
**Vulnerability:** The `difficulty` parameter for the Proof of Work (PoW) challenge solving algorithm in the `edge-sensor` package had no upper bound limit. An excessively high value would cause `solveChallenge` to burn infinite CPU by looping until reaching 100M iterations, causing a DoS.
**Learning:** Input parameters to heavy or repetitive algorithms should always be bounded to prevent resource exhaustion vulnerabilities.
**Prevention:** Always validate loop conditions and input parameters before executing loops with potentially unbounded iterations.
