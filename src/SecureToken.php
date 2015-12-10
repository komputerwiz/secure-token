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
 * An encrypted secure token template that handles signing and encrypting in the proper order while
 * delegating the actual encryptian and signature algorithms to implementing classes
 *
 * All methods used by this class are cryptographically secure.
 */
abstract class SecureToken implements SecureTokenInterface
{
    /**
     * generate a random initialization vector for use in encoding phase
     *
     * @return string
     */
    private function randomInitializationVector()
    {
        $len = $this->getInitializationVectorLength();
        return openssl_random_pseudo_bytes($len);
    }

    /**
     * get signature length in bytes
     *
     * @return integer
     */
    private function getSignatureLength()
    {
        return strlen($this->sign('What is the length of my signature?'));
    }

    /**
     * Verify a signature against a payload
     *
     * @param string $payload
     * @param string $signature
     * @return boolean True if the signature is valid
     */
    private function verify($payload, $signature)
    {
        $trial = $this->sign($payload);
        return $signature === $trial;
    }

    /**
     * {@inheritDoc}
     */
    public function encode($data)
    {
        // encrypt token
        $iv = $this->randomInitializationVector();
        $ciphertext = $this->encrypt($iv, $data);

        // sign encrypted token
        $payload = $iv . $ciphertext;
        $signature = $this->sign($payload);
        return $signature . $payload;
    }

    /**
     * {@inheritDoc}
     */
    public function decode($token)
    {
        // verify signature
        $signatureLength = $this->getSignatureLength();
        $signature = substr($token, 0, $signatureLength);
        $payload = substr($token, $signatureLength);
        if (!$this->verify($payload, $signature)) {
            throw new TokenException('Token has been tampered with', $token);
        }

        // decrypt token
        $ivLength = $this->getInitializationVectorLength();
        $iv = substr($payload, 0, $ivLength);
        $ciphertext = substr($payload, $ivLength);
        return $this->decrypt($iv, $ciphertext);
    }

    /**
     * get initialization vector (IV) length in bytes
     *
     * @return integer
     */
    abstract protected function getInitializationVectorLength();

    /**
     * Cryptographically sign a payload using an HMAC
     *
     * @param string $payload
     * @return string The binary signature
     */
    abstract protected function sign($payload);

    /**
     * Encrypts the given plaintext
     *
     * @param string $iv Initialization vector
     * @param string $plaintext data to encrypt
     * @return string encrypted binary data
     */
    abstract protected function encrypt($iv, $plaintext);

    /**
     * Decrypts the given ciphertext
     *
     * @param string $iv Initialization vector
     * @param string $ciphertext data to decrypt
     * @return string encrypted binary data
     */
    abstract protected function decrypt($iv, $ciphertext);
}
