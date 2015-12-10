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

use Komputerwiz\Security\Token\SecureToken\Aes256CbcSha256SecureToken;
use Komputerwiz\Security\Token\SecureToken\ExpiringSecureToken;
use Komputerwiz\Security\Token\SecureToken\SecureTokenInterface;
use Komputerwiz\Security\Token\SecureToken\TokenException;

class ExpiringSecureTokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * secure token instance for testing
     *
     * @var SecureTokenInterface
     */
    protected $token;

    protected function setUp()
    {
        $encryptionKey = Aes256CbcSha256SecureToken::pbkdf2('testkey1', 'testsalt', 10000);
        $signingKey = Aes256CbcSha256SecureToken::pbkdf2('testkey2', 'testsalt', 10000);
        $delegate = new Aes256CbcSha256SecureToken($encryptionKey, $signingKey);
        $this->token = new ExpiringSecureToken($delegate, new \DateInterval('PT2S'));
    }

    protected function tearDown()
    {
        $this->token = null;
    }

    public function testEncode()
    {
        $data = 'hello world';
        $token = $this->token->encode($data);

        $this->assertTrue(strlen($token) > 0, 'outputs a token');

        return $token;
    }

    /**
     * @depends testEncode
     */
    public function testDecode($token)
    {
        $decrypted = $this->token->decode($token);
        $this->assertEquals($decrypted, 'hello world', 'decodes correctly');
    }

    /**
     * @depends testEncode
     * @expectedException Komputerwiz\Security\Token\SecureToken\TokenException
     */
    public function testDecodeTampering($token)
    {
        $this->token->decode($token . 'tampering');
    }

    /**
     * @depends testEncode
     * @expectedException Komputerwiz\Security\Token\SecureToken\TokenException
     */
    public function testDecodeExpired($token)
    {
        sleep(2);
        $this->token->decode($token);
    }
}
