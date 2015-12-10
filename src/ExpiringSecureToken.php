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
 * Decorator for a secure token that adds an expiration timestamp prior to delegating to the
 * underlying implementation.
 *
 * Decoding a token whose expiration date is in the past will trigger an exception.
 */
class ExpiringSecureToken implements SecureTokenInterface
{
    /**
     * expiration date header length in bytes
     * date is encoded as big-endian unsigned long (32 bits)
     */
    const HEADER_LENGTH = 4;

    /**
     * Existing secure token encoder instance to decorate
     *
     * @var SecureTokenInterface $delegate
     */
    private $delegate;

    /**
     * token lifespan
     *
     * @var \DateInterval $ttl
     */
    private $ttl;


    /**
     * Constructor
     *
     * @param SecureTokenInterface $delegate token instance for encoding data
     * @param DateInterval $ttl token lifespan
     */
    public function __construct(SecureTokenInterface $delegate, \DateInterval $ttl)
    {
        $this->delegate = $delegate;
        $this->ttl = $ttl;
    }


    /**
     * {@inheritDoc}
     */
    public function encode($data)
    {
        $now = new \DateTime();
        $expires = $now->add($this->ttl);
        $header = pack('N', $expires->getTimestamp());
        return $this->delegate->encode($header . $data);
    }

    /**
     * {@inheritDoc}
     */
    public function decode($token)
    {
        // split token into header and data sections
        $token = $this->delegate->decode($token);
        $header = substr($token, 0, self::HEADER_LENGTH);
        $data = substr($token, self::HEADER_LENGTH);

        // unpack and verify expiration date
        $unpacked = unpack('Nexpires', $header);
        $expires = new \DateTime('@' . $unpacked['expires']);
        $now = new \DateTime();
        if ($expires <= $now) {
            throw new TokenException('Token is expired', $token);
        }

        return $data;
    }
}
