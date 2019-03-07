<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional\Profile;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * @group functional
 */
class TransportBindingProfileCreationTest extends WebTestCase
{
    /**
     * @test
     */
    public function aRequestWithoutUsernameCannotBeProcessed(): void
    {
        $content = [
            'displayName' => 'FOO',
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, 'https://locahost/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json'], \Safe\json_encode($content));
        $response = $client->getResponse();
        $data = \Safe\json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'failed');
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'username: This value should not be blank.');
    }

    /**
     * @test
     */
    public function aRequestWithoutDisplayNameCannotBeProcessed(): void
    {
        $content = [
            'username' => 'foo',
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, 'https://locahost/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json'], \Safe\json_encode($content));
        $response = $client->getResponse();
        $data = \Safe\json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'failed');
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'displayName: This value should not be blank.');
    }

    /**
     * @test
     */
    public function aRequestWithADisplayNameCannotBeProcessed(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 123,
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, 'https://locahost/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json'], \Safe\json_encode($content));
        $response = $client->getResponse();
        $data = \Safe\json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'failed');
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'displayName: This value should be of type string.');
    }

    /**
     * @test
     */
    public function aRequestWithAnUsernameNameCannotBeProcessed(): void
    {
        $content = [
            'username' => 123,
            'displayName' => 'FOO',
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, 'https://locahost/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json'], \Safe\json_encode($content));
        $response = $client->getResponse();
        $data = \Safe\json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'failed');
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'username: This value should be of type string.');
    }

    /**
     * @test
     */
    public function aValidRequestProcessed(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 'FOO',
            'authenticatorSelection' => [
                'authenticatorAttachment' => 'cross-platform',
                'userVerification' => 'preferred',
                'requireResidentKey' => true,
            ],
            'attestation' => 'indirect',
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, 'https://locahost/attestation/options', [], [], ['CONTENT_TYPE' => 'application/json'], \Safe\json_encode($content));
        $response = $client->getResponse();
        $data = \Safe\json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'ok');
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], '');

        static::assertArrayHasKey('attestation', $data);
        static::assertEquals($data['attestation'], 'indirect');

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertEquals($data['authenticatorSelection'], ['authenticatorAttachment' => 'cross-platform', 'userVerification' => 'preferred', 'requireResidentKey' => true]);
    }
}
