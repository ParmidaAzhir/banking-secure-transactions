## 1) VALID: issue(create) JWT from transaction data and sign it → encrypt → decrypt+verify
```bash
python src/jwt_issue.py data/transaction_data.json keys/sender_key.pem data/token.jwt

python src/encrypt_packet.py data/token.jwt keys/receiver_cert.pem data/packet.json

python src/decrypt_and_verify.py data/packet.json keys/receiver_key.pem keys/sender_cert.pem keys/ca_cert.pem
```

## 2) Tampered data: change transaction  --- checks if the sender certificate is signed by a trusted CA. Then it verifies the signature of the transaction data
change amount in transaction data
```bash
python src/verify.py data/transaction_data.json data/signature.bin keys/sender_cert.pem keys/ca_cert.pem
## integrity
```
change amount back

## 3) INVALID: wrong receiver key: unautorized reciever tries to decrypt packet using ... and fails.
```bash
python src/decrypt_and_verify.py data/packet.json keys/fake_receiver_key.pem keys/sender_cert.pem keys/ca_cert.pem
## confidentiality
```


## 4) Expired JWT
change to a short lifetime in jwt_issue.py
```bash
python src/jwt_issue.py data/transaction_data.json keys/sender_key.pem data/token.jwt
python src/jwt_verify.py data/token.jwt keys/sender_cert.pem keys/ca_cert.pem
```
change it back to long life time


## 5) Fake Sender
Verification fails because the signature does not match the trusted sender’s public key
```bash
## Sign transaction data with fake sender key 
python src/sign.py data/transaction_data.json keys/fake_sender_key.pem data/signature.bin
##  Verify transaction data that is signed
python src/verify.py data/transaction_data.json data/signature.bin keys/sender_cert.pem keys/ca_cert.pem
## authenticity
```
re run to go to normal:
python src/sign.py data/transaction_data.json keys/sender_key.pem data/signature.bin


## 6) Fake CA
This scenario shows that if sender certificate is signed by a fake CA, it is not trusted, so verification fails
```bash
python src/jwt_verify.py data/fake_token.jwt keys/fake_sender_cert.pem keys/ca_cert.pem
```
verify the fake token using the fake sender’s certificate (signed by a fake CA) and the trusted CA certificate. The verification fails because the certificate is not trusted.

