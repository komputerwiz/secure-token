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
class TimestampedSecureToken implements SecureTokenInterface
{
    /**
     * timestamp header length in bytes
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
     * Constructor
     *
     * @param SecureTokenInterface $delegate token instance for encoding data
     * @param DateInterval $ttl token lifespan
     */
    public function __construct(SecureTokenInterface $delegate)
    {
        $this->delegate = $delegate;
    }


    /**
     * Get the date and time at which the token was issued.
     *
     * @param string $token
     * @return \DateTime
     */
    public function getTimestamp($token)
    {
        $token = $this->delegate->decode($token);
        $header = substr($token, 0, self::HEADER_LENGTH);
        $unpacked = unpack('Nts', $header);
        return new \DateTime('@' . $unpacked['ts']);
    }


    /**
     * {@inheritDoc}
     */
    public function encode($data)
    {
        $now = new \DateTime();
        $header = pack('N', $now->getTimestamp());
        return $this->delegate->encode($header . $data);
    }

    /**
     * {@inheritDoc}
     */
    public function decode($token)
    {
        $token = $this->delegate->decode($token);

        // disregard header section
        return substr($token, self::HEADER_LENGTH);
    }
}
