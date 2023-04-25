# WPA_KRACKs

/***********************************************/

Prerequisites:

We used the latest extended Tamarin prover (version 1.7.1) to produce our formal model. Installation instructions for Tamarin can be found in https://tamarin-prover.github.io/manual/book/002_installation.html.
Moreover, a pre-built binariy of Tamarin version that supports natural number can be found in a docker from Cremers et al. After installing Docker, one simply has to pull the image and enter it to load our models:
docker pull securityprotocolsresearch/tamarin:st
docker run -it securityprotocolsresearch/tamarin:st bash
Note that our verification platform has 16 gigabytes of memory with an Intel i7-9750H CPU. We copyed the latest extended Tamarin prover from the image and one can simply run our models with it.
For example, the following command gives a web GUI(http://127.0.0.1:3001) to explore the details of a formal model:
 ./subterm-tamarin interactive WPA_WNM_new_attack_Fix.spthy


/***********************************************/

Files of the Formal Model:

(1)WPA_plaintext_handshake_init.spthy: A formal model of WPA2 including details and krack attack on the plaintext handshake process.
(2)WPA_plaintext_handshake_race_condition.spthy: A formal model of WPA2 including details and krack attack on the plaintext handshake process. This model allows Supplicant to receive two key installation commands in a row. When Supplicant receives the key installation command again, it still sends the response message in plaintext format. As a result, there are only two encrypted messages in the protocol.
(3)WPA_plaintext_handshake_race_condition_newdefinition.spthy: A formal model of WPA2 including details and krack attack on the plaintext handshake process. This model allows Supplicant to receive two key installation commands in a row. When Supplicant receives the key installation command again, there are more than two encrypted messages in the protocol. If the attack rule with side effects is used, Tamarin will loop to find the source of the unknown ciphertext. Therefore, we used the equivalent Krack attack definition and removed the original attack rule.
(4)WPA_ciphertext_handshake_init.spthy: A formal model of WPA2 including details and krack attack on the ciphertext handshake.
(5)WPA_ciphertext_handshake_race_condition.spthy: A formal model of WPA2 including details and krack attack on the ciphertext handshake. This model allows Supplicant to receive two key installation commands in a row.
(6)WPA_GTK_Init_Attack.spthy: A formal model of WPA2 including details and krack attack on the GTK handshake process.
(7)WPA_GTK_Rekeys.spthy: A model of the GTK handshake process that adds the official early security measures that required the client to keep two keys.
(8)WPA_WNM_init_attack.spthy: A formal model of WPA2 uses the WNM to bypass the earlier official security protections in WPA_GTK_Rekeys.
(9)WPA_WNM_new_attack.spthy: A formal model of WPA2 uses the WNM to bypass the latest official security measures, which require the client to keep four keys.
(10)WPA_WNM_new_attack_Fix.spthy: A defense against the latest attack in which the client randomizes four keys.

The folder Proof contains proofs for all models, while the folder attack_pic contains all attack graphs.
