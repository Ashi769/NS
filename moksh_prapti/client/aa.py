import sys
import smime

message = [
    'To: "Alice" <alice@foo.com>',
    'From: "Bob" <bob@bar.com>',
    'Subject: A message from python',
    '',
    'Now you see me.'
]

with open('signer.pem', 'rb') as pem:
    print(smime.encrypt('\n'.join(message), pem.read()))
