<?php

/**
 * Copyright 2015 Matthew Barry
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Komputerwiz\Security\Token\SecureToken;

/**
 * An encrypted secure token that uses the following cryptographic algorithms:
 *
 *  - AES-256 in CBC mode for encryption
 *  - SHA-256 HMAC for signatures
 *
 * All methods used by this class are cryptographically secure.
 */
class Aes256CbcSha256SecureToken extends SecureToken
{
    const PBKDF2_METHOD = 'sha256';
    const CIPHER_METHOD = 'aes-256-cbc';
    const HMAC_METHOD = 'sha256';

    /**
     * symmetric key to use for encryption
     *
     * @var string $encryptionKey
     */
    private $encryptionKey;

    /**
     * symmetric key to use for signing
     *
     * @var string $signingKey
     */
    private $signingKey;


    /**
     * Constructor
     *
     * @param string $encryptionKey Encryption key
     * @param string $signingKey Signing key (uses $encryptionKey if not provided)
     */
    public function __construct($encryptionKey, $signingKey = null)
    {
        $this->encryptionKey = $encryptionKey;
        $this->signingKey = $signingKey ?: $encryptionKey;
    }


    /**
     * Utility method for deriving a properly sized key for use in this SecureToken
     *
     * @param string $seed
     * @param string $salt
     * @param integer $iterations
     * @return string The generated key
     */
    public static function pbkdf2($seed, $salt, $iterations)
    {
        // HACK: not sure if key size is always the same as block size
        $len = openssl_cipher_iv_length(static::CIPHER_METHOD);
        return hash_pbkdf2(static::PBKDF2_METHOD, $seed, $salt, $iterations, $len, true);
    }

    /**
     * {@inheritDoc}
     */
    protected function getInitializationVectorLength()
    {
        return openssl_cipher_iv_length(static::CIPHER_METHOD);
    }

    /**
     * {@inheritDoc}
     */
    protected function sign($payload)
    {
        return hash_hmac(static::HMAC_METHOD, $payload, $this->signingKey, true);
    }

    /**
     * {@inheritDoc}
     */
    protected function encrypt($iv, $plaintext)
    {
        return openssl_encrypt($plaintext, static::CIPHER_METHOD, $this->encryptionKey, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * {@inheritDoc}
     */
    protected function decrypt($iv, $ciphertext)
    {
        return openssl_decrypt($ciphertext, static::CIPHER_METHOD, $this->encryptionKey, OPENSSL_RAW_DATA, $iv);
    }
}
