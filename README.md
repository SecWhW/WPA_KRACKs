# WPA KRACK Attacks Formal Models

Formal verification models of WPA2 KRACK attacks developed using the Tamarin Prover.

---

## Prerequisites

We used the latest extended Tamarin Prover (version 1.7.1) to produce our formal models.

### Install Tamarin

Installation instructions:

https://tamarin-prover.github.io/manual/book/002_installation.html

### Docker Image

A pre-built Tamarin version supporting natural numbers is available from Cremers et al.

Pull the Docker image:

```bash
docker pull securityprotocolsresearch/tamarin:st
```

Run the container:

```bash
docker run -it securityprotocolsresearch/tamarin:st bash
```

You can copy the extended Tamarin binary from the image and use it to run our models.

### Launch Interactive GUI

For example:

```bash
./subterm-tamarin interactive WPA_WNM_new_attack_Fix.spthy
```

Then open:

```text
http://127.0.0.1:3001
```

to explore the model interactively.

---

## Repository Structure

### Formal Models in `models/` directory

| File | Description |
|--------|-------------|
| `WPA_plaintext_handshake_init.spthy` | WPA2 plaintext handshake model with KRACK attack. |
| `WPA_plaintext_handshake_race_condition.spthy` | Plaintext handshake model allowing two consecutive key installation commands. |
| `WPA_plaintext_handshake_race_condition_newdefinition.spthy` | Alternative attack definition to avoid Tamarin looping on unknown ciphertext sources. |
| `WPA_ciphertext_handshake_init.spthy` | WPA2 ciphertext handshake model with KRACK attack. |
| `WPA_ciphertext_handshake_race_condition.spthy` | Ciphertext handshake model allowing two consecutive key installation commands. |
| `WPA_GTK_Init_Attack.spthy` | GTK handshake KRACK attack model. |
| `WPA_GTK_Rekeys.spthy` | GTK rekeying model implementing the official two-key mitigation. |
| `WPA_WNM_init_attack.spthy` | WNM-based attack bypassing earlier GTK protections. |
| `WPA_WNM_new_attack.spthy` | WNM-based attack bypassing the latest four-key protection. |
| `WPA_WNM_new_attack_Fix.spthy` | Defense model where the client randomizes all four keys. |

---

## Additional Resources

### Proofs

The `Proof/` directory contains proof scripts and verification results for all models.

### Attack Graphs

The `attack_pic/` directory contains attack traces and graphical illustrations of the attacks.

---

## Example

Run the latest defense model:

```bash
./subterm-tamarin interactive WPA_WNM_new_attack_Fix.spthy
```

Open the generated web interface:

```text
http://127.0.0.1:3001
```

to inspect proofs, attack traces, and protocol states.
