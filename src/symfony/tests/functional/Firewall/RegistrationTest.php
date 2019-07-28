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
use Ramsey\Uuid\Uuid;
use function Safe\base64_decode;
use function Safe\json_decode;
use function Safe\json_encode;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @group functional
 */
class RegistrationTest extends WebTestCase
{
    /**
     * @test
     */
    public function aClientCanGetOptionsToRegisterAUser(): void
    {
        $body = [
            'username' => 'foo',
            'displayName' => 'Administrator',
        ];
        $client = static::createClient();
        $client->request('POST', '/register/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com', 'HTTPS' => 'on'], json_encode($body));

        $response = $client->getResponse();
        static::assertEquals(Response::HTTP_OK, $response->getStatusCode());
        $content = json_decode($response->getContent(), true);
        static::assertArrayHasKey('status', $content);
        static::assertEquals('ok', $content['status']);
        static::assertArrayHasKey('errorMessage', $content);
        static::assertEquals('', $content['errorMessage']);
        static::assertArrayHasKey('rp', $content);
        static::assertArrayHasKey('pubKeyCredParams', $content);
        static::assertArrayHasKey('challenge', $content);
        static::assertArrayHasKey('attestation', $content);
        static::assertArrayHasKey('user', $content);
        static::assertArrayHasKey('authenticatorSelection', $content);
        static::assertArrayHasKey('timeout', $content);
    }

    /**
     * @test
     */
    public function aClientCannotSubmitInvalidDataForCreationOptions(): void
    {
        $body = [];
        $client = static::createClient();
        $client->request('POST', '/register/options', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'test.com', 'HTTPS' => 'on'], json_encode($body));

        $response = $client->getResponse();
        static::assertEquals(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertEquals('{"status":"failed","errorMessage":"username: This value should not be blank.\ndisplayName: This value should not be blank."}', $response->getContent());
    }

    /**
     * @test
     */
    public function aUserCanBeAuthenticatedAndAccessToTheProtectedResource(): void
    {
        $userEntity = new PublicKeyCredentialUserEntity('test@foo.com', Uuid::uuid4()->toString(), 'Test PublicKeyCredentialUserEntity');
        $publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('My Application'),
            $userEntity,
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

        $client = static::createClient();
        $session = $client->getContainer()->get('session');
        $session->set('FOO_BAR_SESSION_PARAMETER', [
            'options' => $publicKeyCredentialCreationOptions,
            'userEntity' => $userEntity,
        ]);
        $session->save();

        $assertion = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';

        $client->request('POST', '/register', [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_HOST' => 'localhost', 'HTTPS' => 'on'], $assertion);

        static::assertEquals(Response::HTTP_OK, $client->getResponse()->getStatusCode());
        static::assertEquals('{"status":"ok","errorMessage":""}', $client->getResponse()->getContent());
        static::assertTrue($session->has('_security_main'));

        static::assertTrue($client->getResponse()->headers->has('set-cookie'));

        $client->request('GET', '/page', [], [], ['HTTPS' => 'on']);

        static::assertEquals(Response::HTTP_OK, $client->getResponse()->getStatusCode());
        static::assertEquals('["Page. Hello test@foo.com"]', $client->getResponse()->getContent());
    }
}
