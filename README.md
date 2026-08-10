# GL2 Android attestation mirror

This repository mirrors Google's public Android Key Attestation revocation list.
GitHub Actions fetches the official endpoint every six hours and signs a
48-hour snapshot with an RSA private key stored only in GitHub Actions secrets.

Required repository secret:

- `ATTESTATION_MIRROR_PRIVATE_KEY`: the complete PEM RSA private key.

Run the workflow once with `workflow_dispatch`. The signed snapshot is then
published on the `status` branch at:

`https://raw.githubusercontent.com/<owner>/<repository>/status/android-attestation-snapshot.json`

The application server pins the corresponding public key, verifies every
snapshot, rejects stale snapshots, and never contacts Google during requests.
