# HttpSig: Client-keyed requests with HTTP Message Signatures

## What this repo teaches

This project shows a practical, end-to-end “proof-of-possession” (PoP) flow using **HTTP Message Signatures**:

* The **client generates a key** and proves possession by signing requests.
* The **Authorization Server (AS)** binds the issued access token to that key.
* The **Resource Server (RS)** verifies each request by checking the signature against the **bound** key, not whatever key happens to be in the request.
* Optional: **key rotation** and re-binding.

HTTP Message Signatures are a general tool for authenticated, integrity-protected HTTP traffic. An application or profile decides which parts of a message must be signed, how keys are discovered, and which algs are allowed. 

## Why it matters for real systems

* **Stronger tokens:** Binding tokens to a public key reduces replay and theft risk compared to bearer-only patterns in many deployments. Your RS checks a signature tied to the expected key and rejects substitutions or mixups.
* **Defense in depth:** You decide which components must be covered. Typical profiles require `Authorization`, `@method`, `@target-uri`, and content protection via `Content-Digest`, with a creation time to limit replay windows.
* **Clear responsibility:** The profile must define how the verifier finds the right key (for example by `keyid` or preregistration) and which algorithms are acceptable. That keeps the RS from accepting “any key in the request.”

## What you will see in the code

* Client signs a request using HTTP Message Signatures. The signature base always ends with `@signature-params`, which binds the parameters and prevents partial substitution.
* Requests with bodies include `Content-Digest`, and the RS verifies both the signature and the digest against the received bytes.
* The RS validates that the **key and algorithm are appropriate** for the context, which is essential to prevent “key mixup” attacks.
* Replay resistance with `created` and optional `nonce`.

## Business use cases

* **APIs that must prove “who sent this”**: fintech payments, healthcare data exchange, supply-chain events. The RS can attribute requests to a specific client key instead of just “a valid token was present.”
* **Partner and B2B integrations**: profiles can mandate signed `Authorization` and `Content-Digest` so intermediaries cannot tamper without detection.
* **High-assurance internal microservices**: gateways can request signatures and enforce strict component coverage.

## How this relates to OAuth

HTTP Message Signatures are a general mechanism that any application profile can use. Many OAuth deployments still rely on bearer tokens, but OAuth can adopt PoP profiles too.

## Key implementation notes

* **Select and enforce coverage**. Sign the parts that identify the request and its content. Validate `Content-Digest` against the actual bytes, not just the signature.
* **Define key discovery**. Use `keyid` rules or preregistration so the RS looks up the **bound** key. Do not accept arbitrary keys from the request.
* **Use time and nonce**. Require `created` and consider `nonce` to limit replay.
* **Validate algorithms**. Only allow vetted algorithms and match them to the expected key type.
