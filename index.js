  const jose = require('node-jose');

async function jweEncrypt(alg, contentKeyEncMethod, publicKey, payload) {
  const key = await jose.JWK.asKey(publicKey, 'pem');
  const payloadString = JSON.stringify(payload); // Convert object to JSON string
  const encrypted = await jose.JWE.createEncrypt({ format: 'compact' }, key)
    .update(payloadString) // Use the JSON string as payload
    .final();
  return encrypted;
}

async function jweDecrypt(privateKey, jweEncryptedPayload) {
  const key = await jose.JWK.asKey(privateKey, 'pem');
  const decrypted = await jose.JWE.createDecrypt(key)
    .update(jweEncryptedPayload)
    .final();
  return decrypted.payload.toString();
}

async function jwsSign(privateKey, payloadToSign) { 
  const key = await jose.JWK.asKey(privateKey, 'pem');
  const signed = await jose.JWS.createSign({ format: 'compact' }, key)
    .update(payloadToSign)
    .final();
  return signed;
}

async function jwsVerify(publicKey, signedPayloadToVerify) {
  const key = await jose.JWK.asKey(publicKey, 'pem');
  const verified = await jose.JWS.createVerify(key)
    .verify(signedPayloadToVerify);
  return verified.payload.toString();
}

async function jweEncryptAndSign(publicKeyToEncrypt, privateKeyToSign, payloadToEncryptAndSign) {
  const alg = 'RSA-256';
  const enc = '';
  const encryptedResult = await jweEncrypt(alg, enc, publicKeyToEncrypt, payloadToEncryptAndSign);
  const signedResult = await jwsSign(privateKeyToSign, encryptedResult);
  return signedResult;
}

async function jweVerifyAndDecrypt(publicKeyToVerify, privateKeyToDecrypt, payloadToVerifyAndDecrypt) {
    const verifiedPayload = await jwsVerify(publicKeyToVerify, payloadToVerifyAndDecrypt);
  
    try {
      // Parse the JWS payload to get the encrypted JWE payload
      const jwsObject = jose.JWS.parse(verifiedPayload);
      const encryptedPayload = jwsObject.payload;
  
      // Decrypt the JWE payload
      const decryptedResult = await jweDecrypt(privateKeyToDecrypt, encryptedPayload);
      return decryptedResult;
    } catch (error) {
      // Handle decryption error
      console.error('Decryption error:', error);
      return null;
    }
  }
  

// Example usage
const publicKeyToEncrypt = `-----BEGIN CERTIFICATE-----
MIIDsjCCApoCAQEwDQYJKoZIhvcNAQELBQAwgasxCzAJBgNVBAYTAklOMRQwEgYD
VQQIDAtNYWhhcmFzaHRyYTEPMA0GA1UEBwwGTXVtYmFpMRIwEAYDVQQKDAlBeGlz
IEJhbmsxETAPBgNVBAsMCEFQSSBUZWFtMSUwIwYDVQQDDBxVQVQgSW50ZXJtZWRp
YXRlIENlcnRpZmljYXRlMScwJQYJKoZIhvcNAQkBFhhhcGkuY29ubmVjdEBheGlz
YmFuay5jb20wHhcNMjQwMjEzMTAxODEzWhcNMjUwMTMxMTAxODEzWjCBkTELMAkG
A1UEBhMCSU4xDzANBgNVBAgMBlB1bmphYjEPMA0GA1UEBwwGTW9oYWxpMRIwEAYD
VQQKDAlEaWFsYWJhbmsxDzANBgNVBAsMBlBhaXNzbzESMBAGA1UEAwwJRGlhbGFi
YW5rMScwJQYJKoZIhvcNAQkBFhhnYXVyYXZza2h1cmFuYUBnbWFpbC5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoaDAktvHeXMPCjGUEdkNzew1j
h96cQcfQGqOcJ54+3ptReVDkp4DjQEGoofUByeMZAFHNwcOMI8zIsKH5b1CTrMua
VX/yN9NVk/TPSIbAxgVMYxSvfR2RxN0qjjn7hVPjPQb+e+SvHlsFNGfi2ZG3JaP2
92/3engTNR+u2iFQy6xQxd7/rOtiGp/UojI2tJeOwejeAvleeym2wiAWx0lGnZI4
rqr5QU6aCvUOfNwAXGw6VMg9Gh3PUkHejUOoisInZ5Ld5tUvA7xS+o9BR7VhQMuU
ESuVl4Mnpr7pOM3KH0q5x2F0hq7QueUSIxyp+OsvVbjWRYKYdHTeU0yswsHbAgMB
AAEwDQYJKoZIhvcNAQELBQADggEBAAI9SuIB5kA7zw1iZnqT1JCly4fvwd3PGFix
kl7I5wKDl1//mM6jZnvLQYNpAeKt5YxHtNScN22WFNwhsm2B3ocBtU98iDTEuwgA
UdFWL4oDt4qGF74BcEZezocGPDc6sEOGiE5B2pr3JKxyL4kE2gXS+M/ZRI6qvdHs
2IkgFBAmQx0UY3hHeFtr2EROurveTSje80G5TleSjGu35Wx6h0oeYQweqwlN+JWA
2/NucfqR8cyweMKXwPWfS++FSpvXsUMnvrjQjAmoVkwZY9GYnM+2z/PzGI87BL0Y
diz0GN4d6kBAbRGHwqRUFI8ccfAGXBrMW9FKlP63wLY+Se2HKi0=
-----END CERTIFICATE-----`;


const privateKeyToSign = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/8Vjz1glMyPv0
YsGyo27lufueO47Ba1Oa9zIMN3J57MLUf0dIcGLPYSMA290ktFkCrUdj0XJE3yPq
Ba2QHMsM83zbi02FQ+HcIRoCio0xeY1olV0FCQy3JcSjcqdJmuR8JMEX8Dt7p0vw
Nrt1n/2rDTEPkWpBjyWdc5eLSOKEW7r76V21Vy0aARBEV+RcpK+yXR7ZA/94m/bj
ZvcFxXYXajB4RJvWKrgwhSuQDvuu9oAyxIoy/XLKDUX6eWNAXjLoozR2PiXYNRNy
0eJ8bfSqv5FkcEmhoI83XvK9eM1P6wqXbJ+rn0FHNyM9aMmZj1dz7GOW7E6DU0Ep
ZCa3DE7tAgMBAAECggEAAgW2dLc8GNmDQhNqTAoJyJTZkFS7T9FkK51QIy3QYHV8
pgWDSEGa4Ol6l285mMHnsC4IMwaJaC1bsQMHTZ3oC8Zi+eMxWWaaMhoNLpqsGynX
MhNkzAFI54MX28sA9TcTEjXG7QwkbEyacbj556bcYtl8O1hCYNdzw4FsxtRpQpC6
K4ArsflG5JTqWqM7IvJdIR4aC7PiNHmMDpWf7gGQFaWnl7jN6bM23h2SN4nAJO55
iImHmdiAb25nnbdKc9omfs3ktTbs74Ka07AHtuMRdsF/6xbTiPYVQ7Tzh0lRDZve
xDteN9uZgtbe4YySIpaAfZdXkk7ouX+lkpbCY76RVwKBgQDMp/FIzRf4TiCgWPQv
tIZ0Cg6qTBuBs8xDGt5cFVZwn3PwMuV441uRaInx9p4ENiiP8kXAUNydMvf97x4E
l65yGtYRfe52HmOP4F3VAtp4v191c4oiRQj1uCOnC2nC1+1dmwygl7Ckqlw6QqWz
ML+KeXLjBYbmwf7bx8Wz4Q/lFwKBgQDwGOTqZzzYiHjWaTnlKJTX7wiCVy0dDn8N
o/KiHseYk63d4jw8hz7oALpoFmUJA8o+eZEW2/kPc40DyElTe8nDC5Jeb0VvbN+p
pobPxsWXDJIYYtAMYEGAvCOqhLMnyQb9ldBZ06zaXVDpMdXtYhZmD9rDPxkE/FNx
V9tCREx2mwKBgQDEF+sGcZWVEu8KFRGsIBJwXy6cGB6HEYsXhUgn/T383ZvOPEZJ
pbeYRQ1f7YiMyoPlISOaWSB581tRUet2RQweQv54diyluwp00mu17Wz+I4hI1rM1
kOY74vsuVK46xoCmnyjjO1VDAgUqwa9ZWc091o6xXhtbQeh8GBej+nMrcwKBgBZf
i31YT3AyD2iTd6SmCnCwwo86xmZtwmMoAuUejyTlpg8GFOzjAXanEre+Vn3nj4IQ
2/dQWj4ZW2udz09rOprlSidooQTIFXN+pBNah3ES585D7vUoRxJS9dPe977eWbtp
qXelZPcYOQDx9uhe+o1aLt2A1LkFNlVahYEAUku/AoGAa5HC1Xqa5RlWyDbvLyKj
IT2zNA2+3CCemJGpoy7W5vceBDHumc4fm2V1KsFllHVmZaVolKAyAzVVqp0/L4Ts
1BznLrYclqXFeIG5vUw77FlzKakSCrltfmZEgLbG49GZwajHruhwJTtrdU0/WwvH
rwT93M7Rh8W8gvuN497C+Tg=
-----END PRIVATE KEY-----`;


const publicKeyToVerify = `-----BEGIN CERTIFICATE-----
MIIDsjCCApoCAQEwDQYJKoZIhvcNAQELBQAwgasxCzAJBgNVBAYTAklOMRQwEgYD
VQQIDAtNYWhhcmFzaHRyYTEPMA0GA1UEBwwGTXVtYmFpMRIwEAYDVQQKDAlBeGlz
IEJhbmsxETAPBgNVBAsMCEFQSSBUZWFtMSUwIwYDVQQDDBxVQVQgSW50ZXJtZWRp
YXRlIENlcnRpZmljYXRlMScwJQYJKoZIhvcNAQkBFhhhcGkuY29ubmVjdEBheGlz
YmFuay5jb20wHhcNMjQwMjEzMTAxODEzWhcNMjUwMTMxMTAxODEzWjCBkTELMAkG
A1UEBhMCSU4xDzANBgNVBAgMBlB1bmphYjEPMA0GA1UEBwwGTW9oYWxpMRIwEAYD
VQQKDAlEaWFsYWJhbmsxDzANBgNVBAsMBlBhaXNzbzESMBAGA1UEAwwJRGlhbGFi
YW5rMScwJQYJKoZIhvcNAQkBFhhnYXVyYXZza2h1cmFuYUBnbWFpbC5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoaDAktvHeXMPCjGUEdkNzew1j
h96cQcfQGqOcJ54+3ptReVDkp4DjQEGoofUByeMZAFHNwcOMI8zIsKH5b1CTrMua
VX/yN9NVk/TPSIbAxgVMYxSvfR2RxN0qjjn7hVPjPQb+e+SvHlsFNGfi2ZG3JaP2
92/3engTNR+u2iFQy6xQxd7/rOtiGp/UojI2tJeOwejeAvleeym2wiAWx0lGnZI4
rqr5QU6aCvUOfNwAXGw6VMg9Gh3PUkHejUOoisInZ5Ld5tUvA7xS+o9BR7VhQMuU
ESuVl4Mnpr7pOM3KH0q5x2F0hq7QueUSIxyp+OsvVbjWRYKYdHTeU0yswsHbAgMB
AAEwDQYJKoZIhvcNAQELBQADggEBAAI9SuIB5kA7zw1iZnqT1JCly4fvwd3PGFix
kl7I5wKDl1//mM6jZnvLQYNpAeKt5YxHtNScN22WFNwhsm2B3ocBtU98iDTEuwgA
UdFWL4oDt4qGF74BcEZezocGPDc6sEOGiE5B2pr3JKxyL4kE2gXS+M/ZRI6qvdHs
2IkgFBAmQx0UY3hHeFtr2EROurveTSje80G5TleSjGu35Wx6h0oeYQweqwlN+JWA
2/NucfqR8cyweMKXwPWfS++FSpvXsUMnvrjQjAmoVkwZY9GYnM+2z/PzGI87BL0Y
diz0GN4d6kBAbRGHwqRUFI8ccfAGXBrMW9FKlP63wLY+Se2HKi0=
-----END CERTIFICATE-----`;

const privateKeyToDecrypt = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/8Vjz1glMyPv0
YsGyo27lufueO47Ba1Oa9zIMN3J57MLUf0dIcGLPYSMA290ktFkCrUdj0XJE3yPq
Ba2QHMsM83zbi02FQ+HcIRoCio0xeY1olV0FCQy3JcSjcqdJmuR8JMEX8Dt7p0vw
Nrt1n/2rDTEPkWpBjyWdc5eLSOKEW7r76V21Vy0aARBEV+RcpK+yXR7ZA/94m/bj
ZvcFxXYXajB4RJvWKrgwhSuQDvuu9oAyxIoy/XLKDUX6eWNAXjLoozR2PiXYNRNy
0eJ8bfSqv5FkcEmhoI83XvK9eM1P6wqXbJ+rn0FHNyM9aMmZj1dz7GOW7E6DU0Ep
ZCa3DE7tAgMBAAECggEAAgW2dLc8GNmDQhNqTAoJyJTZkFS7T9FkK51QIy3QYHV8
pgWDSEGa4Ol6l285mMHnsC4IMwaJaC1bsQMHTZ3oC8Zi+eMxWWaaMhoNLpqsGynX
MhNkzAFI54MX28sA9TcTEjXG7QwkbEyacbj556bcYtl8O1hCYNdzw4FsxtRpQpC6
K4ArsflG5JTqWqM7IvJdIR4aC7PiNHmMDpWf7gGQFaWnl7jN6bM23h2SN4nAJO55
iImHmdiAb25nnbdKc9omfs3ktTbs74Ka07AHtuMRdsF/6xbTiPYVQ7Tzh0lRDZve
xDteN9uZgtbe4YySIpaAfZdXkk7ouX+lkpbCY76RVwKBgQDMp/FIzRf4TiCgWPQv
tIZ0Cg6qTBuBs8xDGt5cFVZwn3PwMuV441uRaInx9p4ENiiP8kXAUNydMvf97x4E
l65yGtYRfe52HmOP4F3VAtp4v191c4oiRQj1uCOnC2nC1+1dmwygl7Ckqlw6QqWz
ML+KeXLjBYbmwf7bx8Wz4Q/lFwKBgQDwGOTqZzzYiHjWaTnlKJTX7wiCVy0dDn8N
o/KiHseYk63d4jw8hz7oALpoFmUJA8o+eZEW2/kPc40DyElTe8nDC5Jeb0VvbN+p
pobPxsWXDJIYYtAMYEGAvCOqhLMnyQb9ldBZ06zaXVDpMdXtYhZmD9rDPxkE/FNx
V9tCREx2mwKBgQDEF+sGcZWVEu8KFRGsIBJwXy6cGB6HEYsXhUgn/T383ZvOPEZJ
pbeYRQ1f7YiMyoPlISOaWSB581tRUet2RQweQv54diyluwp00mu17Wz+I4hI1rM1
kOY74vsuVK46xoCmnyjjO1VDAgUqwa9ZWc091o6xXhtbQeh8GBej+nMrcwKBgBZf
i31YT3AyD2iTd6SmCnCwwo86xmZtwmMoAuUejyTlpg8GFOzjAXanEre+Vn3nj4IQ
2/dQWj4ZW2udz09rOprlSidooQTIFXN+pBNah3ES585D7vUoRxJS9dPe977eWbtp
qXelZPcYOQDx9uhe+o1aLt2A1LkFNlVahYEAUku/AoGAa5HC1Xqa5RlWyDbvLyKj
IT2zNA2+3CCemJGpoy7W5vceBDHumc4fm2V1KsFllHVmZaVolKAyAzVVqp0/L4Ts
1BznLrYclqXFeIG5vUw77FlzKakSCrltfmZEgLbG49GZwajHruhwJTtrdU0/WwvH
rwT93M7Rh8W8gvuN497C+Tg=
-----END PRIVATE KEY-----`;

const payloadToEncryptAndSign = {
    "Data": {
      "userName": "alwebuser",
      "password": "acid_qa"
    },
    "Risks": {}
  };

jweEncryptAndSign(publicKeyToEncrypt, privateKeyToSign, payloadToEncryptAndSign)
  .then(signedResult => {
    console.log('Encrypted and Signed:', signedResult);

    // Example: Verify and Decrypt
    jweVerifyAndDecrypt(publicKeyToVerify, privateKeyToDecrypt, signedResult)
      .then(decryptedResult => {
        console.log('Decrypted Result:', decryptedResult);
      })
      .catch(error => {
        console.error('Verification and Decryption error:', error);
      });
  })
  .catch(error => {
    console.error('Encryption and Signing error:', error);
  });
