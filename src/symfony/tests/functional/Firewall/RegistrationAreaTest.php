<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional\Firewall;

use Cose\Algorithms;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Tests\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Tests\Functional\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Tests\Functional\User;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @group functional
 */
class RegistrationAreaTest extends WebTestCase
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
        $client->request(Request::METHOD_POST, '/register/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'error');
        static::assertEquals(401, $client->getResponse()->getStatusCode());
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
        $client->request(Request::METHOD_POST, '/register/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'error');
        static::assertEquals(401, $client->getResponse()->getStatusCode());
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
        $client->request(Request::METHOD_POST, '/register/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'error');
        static::assertEquals(401, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'displayName: This value should be of type string.');
    }

    /**
     * @test
     */
    public function aRequestWithAnInvalidUsernameCannotBeProcessed(): void
    {
        $content = [
            'username' => 123,
            'displayName' => 'FOO',
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/register/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'error');
        static::assertEquals(401, $client->getResponse()->getStatusCode());
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
        $client->request(Request::METHOD_POST, '/register/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'ok');
        static::assertEquals(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], '');

        static::assertArrayHasKey('attestation', $data);
        static::assertEquals($data['attestation'], 'indirect');

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertEquals($data['authenticatorSelection'], ['authenticatorAttachment' => 'cross-platform', 'userVerification' => 'preferred', 'requireResidentKey' => true]);
    }

    /**
     * @test
     */
    public function aValidRequestProcessedOnOtherHost(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 'FOO',
            'authenticatorSelection' => ['requireResidentKey' => true],
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/register/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'foo.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'ok');
        static::assertEquals(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], '');

        static::assertArrayHasKey('attestation', $data);
        static::assertEquals('none', $data['attestation']);

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertEquals(['userVerification' => 'preferred', 'requireResidentKey' => true], $data['authenticatorSelection']);
    }

    /**
     * @test
     */
    public function aValidRequestProcessedWithExtensions(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 'FOO',
            'authenticatorSelection' => [
                'authenticatorAttachment' => 'platform',
                'userVerification' => 'required',
                'requireResidentKey' => true,
            ],
            'extensions' => [
                'loc' => true,
                'def' => '123',
            ],
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/register/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'ok');
        static::assertEquals(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], '');

        static::assertArrayHasKey('attestation', $data);
        static::assertEquals('none', $data['attestation']);
        static::assertEquals(['loc' => true, 'def' => '123'], $data['extensions']);

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertEquals(['authenticatorAttachment' => 'platform', 'userVerification' => 'required', 'requireResidentKey' => true], $data['authenticatorSelection']);
    }

    /**
     * @test
     */
    public function aRegistrationOptionsRequestCannotBeAcceptedForExistingUsers(): void
    {
        $content = [
            'username' => 'admin',
            'displayName' => 'Admin',
        ];
        $client = self::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_POST, '/register/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'error');
        static::assertEquals(401, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'Invalid username');
    }

    /**
     * @test
     */
    public function aRegistrationResultRequestCannotBeAcceptedIfNoOptionsAreAvailableInTheStorage(): void
    {
        $content = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';

        $client = self::createClient([], ['HTTPS' => 'on']);
        $session = $client->getContainer()->get('session');
        $session->remove('FOO_BAR_SESSION_PARAMETER');
        $session->save();

        $client->request(Request::METHOD_POST, '/register', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com'], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'error');
        static::assertEquals(401, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], 'No public key credential options available for this session.');
    }

    /**
     * @test
     */
    public function aValidRegistrationResultRequestIsCorrectlyManaged(): void
    {
        $publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity');
        $publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('My Application'),
            $publicKeyCredentialUserEntity,
            base64_decode('9WqgpRIYvGMCUYiFT20o1U7hSD193k11zu4tKP7wRcrE26zs1zc4LHyPinvPGS86wu6bDvpwbt8Xp2bQ3VBRSQ==', true),
            [
                new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256),
            ],
            60000,
            [],
            new AuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            new AuthenticationExtensionsClientInputs()
        );

        $content = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';

        $client = self::createClient([], ['HTTPS' => 'on']);
        $pkcsRepository = $client->getContainer()->get(PublicKeyCredentialSourceRepository::class);
        $pkcsRepository->clearCredentials();
        $session = $client->getContainer()->get('session');
        $session->set('FOO_BAR_SESSION_PARAMETER', [
            'options' => $publicKeyCredentialCreationOptions,
            'userEntity' => $publicKeyCredentialUserEntity,
        ]);
        $session->save();

        $client->request(Request::METHOD_POST, '/register', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'localhost'], $content);
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertEquals($data['status'], 'ok');
        static::assertEquals(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertEquals($data['errorMessage'], '');

        $pkueRepository = $client->getContainer()->get(PublicKeyCredentialUserEntityRepository::class);
        $user = $pkueRepository->findOneByUsername('test@foo.com');
        static::assertInstanceOf(User::class, $user);

        static::assertTrue($session->has('_security_main'));
        static::assertTrue($client->getResponse()->headers->has('set-cookie'));
    }
}
