## Introduction

This report examines the SecTrans project, designed to provide a secure file transfer solution. Emphasizing practicality and security, the project navigates the complexities of data protection, offering a model for balancing efficiency with cybersecurity needs in a professional setting.

## Our choice of architecture

1. **System Architecture:**

The SecTrans project is built around a client-server architecture. The central server manages requests from multiple clients. The server application, located on the company's infrastructure, is responsible for managing files and authenticating users. The client, used by employees, allows for downloading, uploading, and listing files. The architecture integrates two main binaries in the Executables folder: one to start the server and another for the client application.

2. **Security Architecture:**

The project utilizes Diffie-Hellman key exchange to securely establish a shared secret key between two parties. This shared secret key is used as the key for AES encryption in CBC mode during the session. The size of a key currently is 128-bits, which is considered secure enough and cannot be broken through the brute algorithm (unless it is a quantum computer). Also, this method is fast taking into account AES hardware acceleration. In fact, it is much faster than RSA and is preferable for securing file transfers because they might be extremely big.

For now we use a weaker version of Diffie-Hellman public parameters. According to the modern security standards (Table 1), in order to be at the same level with AES-128, we must generate the public parameters of the 3072-bit size, which we do not do.

![keys_rec.png](images%2Fkeys_rec.png)

However, if we increase the bit size to 3072 to meet security levels for an equivalent AES-128 key we find it takes about 18 minutes to generate the safe prime on a mid-2009 Core 2 Duo. Because we are unaware which chip our company-client uses in their server to host the application, we cannot recommend implementing this size of public parameters because of the time issues.

In order to be able to meet the modern security standards and also not to run out of time while generating the public parameters, it is preferable to move to Elliptic Curve Diffie-Hellman later. As we can see from Table 1, it is sufficient to have the size only of 256 to meet the standards. That is the window for the project improvement in future perspective.

The common problem which is usually faced with the use of Diffie-Hellman algorithm is a Man in the Middle attack (MITM). MITM is a cyberattack where the attacker secretly relays and possibly alters the communications between two parties who believe that they are directly communicating with each other, as the attacker has inserted themselves between the two parties. To secure our application we have integrated the authentication of the clients with the further JSON Web Token (JWT) check. So, what is happening in reality? After key exchange, the client sends credentials and the server responses with a JWT, which the client then uses in each request (Figure 1).

![token.jpeg](images%2Ftoken.jpeg)

Figure 1- A token based authentication

However, Man in the Middle attack on the client (when criminals act like the server to steal client data) is still possible due to absence of certificate authority (CA) that would be able to verify the server’s certificate. This additional security measure is already an advanced level security development and is absolutely out of the scope of this project.

Another interesting point which is worth mentioning is how the server stores the users’ passwords. It is not secure to store them in value because some users may reuse the same password for different resources. And generally speaking, applications do not store passwords in plaintext, but instead calculate a cryptographic hash function value. After the users send their passwords to log in, it is converted to hash, and the result is compared with the stored hashes on the server to look for a match. If they match, the user is authenticated and able to login to the application. That is why we have implemented password hashing utilizing the SHA-256 algorithm on the server side. This measure enhances the security of user data in case of a storage compromise, preventing potential criminals from restoring users' passwords.

However, just a hash function is not always enough. There exists such a technique of crypto attack called the rainbow table, which itself refers to a precomputed table that contains the password hash value for each plain text character used during the authentication process. If hackers gain access to the list of plain password hashes, they can crack passwords with a rainbow table. In order to exclude this vulnerability, a random 128-bit salt is applied to each password, making it impossible to use a rainbow table attack as well.

Finally, our program system is vulnerable to the well known Spectre attacks class, because the library has not provided the fix for it yet. The Spectre attack exploits a vulnerability stemming from the presence of branch prediction mechanisms in modern processors. These mechanisms are designed to optimize the execution of instructions by predicting the likely outcome of conditional branches. Using the Spectre attack, it is possible to gain access to private data. However, this vulnerability is beyond the scope of this course as well.

## Technological Choices and Cryptographic Practices

1. **Cryptographic<a name="_page5_x72.00_y496.52"></a> Library:**

Our project employs the Crypto++ library (version 8.90), which is crucial for implementing advanced cryptographic functions. It's essential to monitor for timing leaks within the library, a potential risk during key generation. This library's choice aligns with our security objectives, providing robust encryption capabilities.

[Link to Crypto++8.90](https://www.cryptopp.com/release890.html)

2. **Algorithm<a name="_page5_x72.00_y697.09"></a> and Encryption:**

We opted for the Diffie-Hellman algorithm for key exchange, coupled with 128-bit AES in CBC Mode. This decision prioritizes speed and security, considering AES's hardware acceleration benefits. This symmetric cipher approach, as opposed to asymmetric methods like RSA, ensures faster and more secure key generation at each session.

## Evaluation

**1. Demo**

i. Security<a name="_page6_x72.00_y199.95"></a> and Precautions:
- Executable Integrity: To maintain the integrity of the security configurations, please do not attempt to rebuild or modify the executables. Rebuilding them would necessitate installing the Crypto++ library on your system, which is an additional step we aim to avoid.
- Hardware Configuration: Carefully configure your system to reduce the risk of side-channel attacks. This includes measures like disabling hyperthreading on CPUs if necessary to enhance the overall security of the system.

ii. Video<a name="_page6_x72.00_y427.76"></a> of Demonstration:

[https://www.canva.com/design/DAF5VE54SwA/WiNnklvLHfP NFlxt6pn5SQ/watch?utm_content=DAF5VE54SwA&utm_campai gn=designshare&utm_medium=link&utm_source=editor](https://www.canva.com/design/DAF5VE54SwA/WiNnklvLHfPNFlxt6pn5SQ/watch?utm_content=DAF5VE54SwA&utm_campaign=designshare&utm_medium=link&utm_source=editor)

iii. Steps Of Demonstration :

1. First, move to the ``/Executables`` folder. This is where the magic happens✨
2. On your very first launch, please install the shared libraries sudo ``./install_deps.sh``
3. Launch the Server ``./secureServer``
4. Open another terminal and launch the Client
```sh
./sectrans
   Login : Mariia
   Password : secure\_password
```

5. Upload Files

   To upload files, you put the files in ``/Executables`` folder and do this command
```sh
   ./sectrans -up {your_file_name}
```

6. Download Files
```sh
   ./sectrans -down {your_file_name}
```
You will then find the downloaded files in ``/clientFiles``

7. List all the files available in the server
```sh
   ./sectrans -list
```
2. **What we accomplished**

In topics which we had during the course:


|**Topic**| **Oursolution**                                                                                                                                                        |
| - |------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|SQL injection| We do not have SQL                                                                                                                                                     |
|CSRF| JWT                                                                                                                                                                    |
|XSS| It’s not a web app                                                                                                                                                     |
|Buffer Overflow| Fixes needed                                                                                                                                                           |
|Threads attack| <p>Can be optionally handled by disabling</p><p>hyperthreading</p>                                                                                                     |
|Statistical analysis| We should not provide the server-side code                                                                                                                             |
|DDOS attacks| There is a possibility. The company should host their server at the secured private network and allow access only via VPN or the direct network access (at the office) |

3. **Security Analysis**

- Crypto++library issues and remediation

  Crypto++ attempts to resist side channel attacks using various remediation. The remediation is applied as the best effort, but is probably incomplete. They are incomplete due to CPU speculation bugs like Spectre, Meltdown, Foreshadow. The attacks target both CPU caches and internal buffers.

  The library uses hardware instructions when possible for block ciphers, hashes and other operations. The hardware acceleration remediates some timing attacks. The library also uses cache-aware algorithms and access patterns to minimize leakage of cache evictions.

  Elliptic curves over binary fields are believed to leak information. But elliptic curves over binary fields are not used in the project.

  Crypto++does not engage Specter remediation at this time.

  To help resist attacks, hyperthreading on CPUs may be disabled, but it will hit performance and is not recommended at server side.

## References

- Cryptopp library h[ttps://www.cryptopp.com/release890.html](https://www.cryptopp.com/release890.html)
- Diffie-Hellman algorithm [https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_ex change](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- Is there a key length definition for DH or DHE? [https://security.stackexchange.com/questions/42558/is-there- a-key-length-definition-for-dh-or-dhe](https://security.stackexchange.com/questions/42558/is-there-a-key-length-definition-for-dh-or-dhe)
- NIST recommended key sizes [https://qph.cf2.quoracdn.net/main-qimg-7c90a12b25b248f90b5 204a290b13213-lq](https://qph.cf2.quoracdn.net/main-qimg-7c90a12b25b248f90b5204a290b13213-lq)
