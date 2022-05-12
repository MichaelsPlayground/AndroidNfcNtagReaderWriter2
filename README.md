# AndroidNfcNtagReaderWriter

To run this project you need a real device with NFC-support and NFC-Tags. I used NTAG216 for my tests and everything run as expected.

The NCF-code is based on an stackoverflow.com answer:

https://stackoverflow.com/questions/64920307/how-to-write-ndef-records-to-nfc-tag

author: user Andrew, answered Nov 19, 2020 at 23:13

This app is tested with Samsung A5 (Android 8) and Samsung A51 (Android 12) together with NFC-Tags NTAG216.

There are 3 activites available:

1) MainActivity:

Reads a tag and tries to read a NDEF formatted message stored on the tag, then displays the records. 

If the tag contains encrypted data 
that was created by the WriteCiphertext activity a notice is shown and there is an input field for the passphrase and a 
DECRYPT button - the original (decrypted) plaintext will be shown.

2) WriteTag activity:

Writes a NDEF formatted message on the tag. 

**Be careful, a discovered tag will get overwritten when this activity is 
in the foreground !**

There are 3 records in the message:

a) NDEF text record, containing a text that will be appended by an actual timestamp

b) NDEF uri record, containing the fixed url "http://androidcrypto.bplaced.net"

c) NDEF aar record, containing the Android Application Record "de.androidcrypto.ntagapp". This is the package name 
of this app so the app will get started if a tag written by this activity is presented on an Androind Smartphone. 
If the app is not installed on the Smartphone the smartphone tries to load the app from the PlayStore (as the app 
is not listed there it will not find this app).

3) WriteCiphertext activity:

This is an advanced version of the data written by the WriteTag activity. Enter a plaintext and passphrase in the fields 
and press ENCRYPT to encrypt the plaintext with AES-256 algorithm in GCM mode. The key is derived from the passphrase 
using PBKDF2 algorithm with SHA-256 hash algorithm and 10000 iterations. The tag will be written ONLY when data got 
encrypted.

**Be careful, a discovered tag will get overwritten when this activity is in the foreground  and 
encrypted data are available !**

a) NDEF text record, containing the text "Encryption was done with AES-256 GCM PBKDF2 on " append by an actual timestamp.

b) NDEF external record, containing the domain "de.androidcrypto.aes256gcmpbkdf2" and type "salt". The payload takes 
the random SALT used by the key derivation.

c) NDEF external record, containing the domain "de.androidcrypto.aes256gcmpbkdf2" and type "nonce". The payload takes
the random nonce used by the AES encryption.

d) NDEF external record, containing the domain "de.androidcrypto.aes256gcmpbkdf2" and type "ciphertext". The payload takes
the CIPHERTEXT (the result of the AES encryption).

e) NDEF uri record, containing the fixed url "http://androidcrypto.bplaced.net"

f) NDEF aar record, containing the Android Application Record "de.androidcrypto.ntagapp". This is the package name
of this app so the app will get started if a tag written by this activity is presented on an Androind Smartphone.
If the app is not installed on the Smartphone the smartphone tries to load the app from the PlayStore (as the app
is not listed there it will not find this app).

The plaintext data is limited to 50 characters. As the NTAG216 has a total message size of 868 bytes you could extend 
the plaintext size to 550 bytes without getting any problems.

**SERIOUS WARNING: the encryption scheme that is used for en- / decryption is not breakable in any way. If you forget the 
passphrase there is NO WAY to recover the plaintext and brute force will be your only chance to get access to the data.**

Last modification: May 12th. 2022

If you like to contact me use the data in my GitHub profile or this Email address: androidcrypto@gmx.de, thanks.


