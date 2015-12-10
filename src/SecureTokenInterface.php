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

interface SecureTokenInterface
{
    /**
     * Encodes arbitrary binary data into a cryptographically secure token.
     *
     * The returned value is raw binary data: be sure to base64_encode it!
     *
     * @param string $data
     * @return string
     */
    public function encode($data);

    /**
     * Decodes a binary secure token into its original plaintext content.
     *
     * @param string $token
     * @return string
     * @throws TokenException on invalid token (e.g. tampered, expired)
     */
    public function decode($token);
}
