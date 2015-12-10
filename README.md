# SecureToken Library

Encrypt sensitive data and use the resulting ciphertext as a memento for your applications.

In circumstances of user import or generation, email verification, and/or lost credentials, it is commonplace to send an email with a temporary link to a page where the target user can reset his or her password. Sometimes the state (a generated nonce, request expiration, etc.) of such a transaction is stored on the user account in the server's database. This requires extra maintenance. Instead, the pertinent transaction information can be externalized in a token. If done incorrectly, intercepting and tampering with tokens could allow an attacker to gain unwanted access to an account. The solution presented by this library offers a cryptographically secure means of externalizing state in a token: data is encrypted to ensure confidentiality and then signed to ensure integrity.


## Installation

Add the following to your **composer.json**:

    require: {
        "komputerwiz/secure-token": "dev-master"
    }

## Usage

Available encryption methods are:

* AES 256 in CBC mode with SHA-512 HMAC signature (**Komputerwiz\\Security\\Token\\SecureToken\\Aes256CbcSha512SecureToken**)
* AES 256 in CBC mode with SHA-256 HMAC signature (**Komputerwiz\\Security\\Token\\SecureToken\\Aes256CbcSha256SecureToken**)

I will try to implement more as PHP cryptography improves (e.g. once [AES 256 GCM][] is supported). Feel free to implement your own and submit a pull request, too!

```php
<?php

use Komputerwiz\Security\Token\SecureToken\Aes256CbcSha256SecureToken;
use Komputerwiz\Security\Token\SecureToken\ExpiringSecureToken;
use Komputerwiz\Security\Token\SecureToken\TokenException;

// helper PBKDF2 method for deriving a key from a secret; not required, but recommended
$encryptionKey = Aes256CbcSha256SecureToken::pbkdf2('secret', 'salt', 10000);
$signingKey = Aes256CbcSha256SecureToken::pbkdf2('secret', 'salt', 10000);

// if only one key is provided, that key will be used for both encrypting and signing
$token = new Aes256CbcSha256SecureToken($encryptionKey, $signingKey);


// optionally wrap it in an ExpiringSecureToken so that it will not be accepted after a set interval
$token = new ExpiringSecureToken($token);


$data = 'set your super secret data here';
$binaryToken = $token->encode($data)

// Do something with the $binaryToken. If it needs to be printed in ASCII text,
// be sure to base64_encode it and base64_decode it before the next step!


try {
    $data = $token->decode($binaryToken);
} catch (TokenException $e) {
    // token was either tampered with or expired
}
```

## Implementing Your Own SecureToken

There are two ways to implement your own SecureToken encoder:

### Implement **Komputerwiz\\Security\\Token\\SecureToken\\SecureTokenInterface**.

This way gives you the most freedom to do what you want, but it's up to you to guarantee security. This might be better for implementing a decorator that delegates to an existing SecureToken implementation.

```php
<?php

use Komputerwiz\Security\Token\SecureToken\SecureTokenInterface;

class MySecureTokenDecorator implements SecureTokenInterface
{
    /**
     * @var SecureTokenInterface $token
     */
    private $token;
    
    
    public function __construct(SecureTokenInterface $token)
    {
        $this->token = $token;
    }
    
    /**
     * {@inheritDoc}
     */
    public function encode($data)
    {
        // do something with $data to suit your needs (e.g. adding a header)
        
        return $this->token->encode($data);
    }
    
    /**
     * {@inheritDoc}
     */
    public function decode($token)
    {
        $data = $this->token->decode($token);
        
        // perform additional validity checks and/or modify $data
        
        return $data;
    }
}
```

### Extend **Komputerwiz\\Security\\Token\\SecureToken\\SecureToken**

This way adheres to the well-known encrypt and sign paradigm. It takes care of generating an input vector and calling out to encrypt, decrypt, and sign methods that you implement yourself.

```php
<?php

use Komputerwiz\Security\Token\SecureToken\SecureToken;

class MySecureToken extends SecureToken
{
    /**
     * {@inheritDoc}
     */
    protected function getInitializationVectorLength()
    {
        // calculate input vector size (usually block size of algorithm)
        // @see openssl_cipher_iv_length($cipher)
        return $length;
    }

    /**
     * {@inheritDoc}
     */
    protected function sign($payload)
    {
        // generate signature for $payload
        return $signature;
    }

    /**
     * {@inheritDoc}
     */
    protected function encrypt($iv, $plaintext)
    {
        // encrypt $plaintext using init. vector $iv if necessary
        return $encrypted;
    }

    /**
     * {@inheritDoc}
     */
    protected function decrypt($iv, $ciphertext)
    {
        // decrypt $ciphertext using init. vector $iv if necessary
        return $decrypted;
    }
}
```



## License

Copyright 2015 Matthew Barry

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[aes 256 gcm]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
