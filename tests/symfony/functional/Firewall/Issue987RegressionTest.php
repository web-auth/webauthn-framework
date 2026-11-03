<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use Cose\Algorithms;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\CustomSessionStorage;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialUserEntityRepository;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;

/**
 * Issue #987: WebAuthn defines a single credential type, "public-key", but a credential of any other type was accepted
 * and the ceremony that followed succeeded. The FIDO Conformance Tools check it in
 * Server-ServerAuthenticatorAttestationResponse-Resp-1 F-6 and Server-ServerAuthenticatorAssertionResponse-Resp-1 F-6.
 * The registration of RegistrationAreaTest and the authentication of LegacySecuredAreaTest, base64url encoded as a
 * client sends them and with their options in the storage, are now rejected when only their type changes, with the
 * InvalidDataException of the denormalizer.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/987
 * @internal
 */
final class Issue987RegressionTest extends WebauthnTestCase
{
    #[Test]
    public function aRegistrationWithACredentialOfAnotherTypeIsRejected(): void
    {
        $publicKeyCredentialUserEntity = PublicKeyCredentialUserEntity::create(
            'test@foo.com',
            random_bytes(64),
            'Test PublicKeyCredentialUserEntity'
        );
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create(),
            $publicKeyCredentialUserEntity,
            base64_decode(
                '9WqgpRIYvGMCUYiFT20o1U7hSD193k11zu4tKP7wRcrE26zs1zc4LHyPinvPGS86wu6bDvpwbt8Xp2bQ3VBRSQ==',
                true
            ),
            [PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_ES256)]
        );
        $credentialId = Base64UrlSafe::decodeNoPadding(
            'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK'
        );
        $content = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"other","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3-hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R_Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW-aM9YYyYnUTJ"}}';

        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $userEntityRepository = $client->getContainer()
            ->get(PublicKeyCredentialUserEntityRepository::class);
        $userEntityRepository->ensureUserDoesNotExist('test@foo.com');
        $credentialRepository = $client->getContainer()
            ->get(PublicKeyCredentialSourceRepository::class);
        $credentialRepository->ensureCredentialNotExist($credentialId);

        $storage = static::getContainer()->get(CustomSessionStorage::class);
        $storage->store(Item::create($publicKeyCredentialCreationOptions, $publicKeyCredentialUserEntity));

        $client->request(Request::METHOD_POST, '/api/register', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], $content);

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        static::assertSame(
            [
                'status' => 'error',
                'errorMessage' => 'Invalid parameter "type". Shall be "public-key".',
            ],
            json_decode((string) $client->getResponse()->getContent(), true, 512, JSON_THROW_ON_ERROR)
        );
        static::assertNull($userEntityRepository->findOneByUsername('test@foo.com'));
        static::assertNull($credentialRepository->findOneByCredentialId($credentialId));
        static::assertFalse($client->getRequest()->getSession()->has('_security_main'));
    }

    #[Test]
    public function anAuthenticationWithACredentialOfAnotherTypeIsRejected(): void
    {
        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true)
        );
        $publicKeyCredentialRequestOptions->timeout = 60000;
        $publicKeyCredentialRequestOptions->rpId = 'localhost';
        $publicKeyCredentialRequestOptions->userVerification = PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED;
        $publicKeyCredentialRequestOptions->allowCredentials = [
            PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Base64UrlSafe::decodeNoPadding(
                    'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w'
                )
            ),
        ];
        $assertion = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"other","rawId":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY_vcNkbo_LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w_8RGiZzE-gOM61ffxmgEDeyhM","userHandle":null}}';

        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $storage = static::getContainer()->get(CustomSessionStorage::class);
        $storage->store(Item::create(
            $publicKeyCredentialRequestOptions,
            PublicKeyCredentialUserEntity::create('admin', 'foo', 'Foo BAR (-_-)')
        ));

        $client->request(Request::METHOD_POST, '/api/login', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], $assertion);

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        static::assertSame(
            [
                'status' => 'error',
                'errorMessage' => 'Invalid parameter "type". Shall be "public-key".',
            ],
            json_decode((string) $client->getResponse()->getContent(), true, 512, JSON_THROW_ON_ERROR)
        );
        static::assertFalse($client->getRequest()->getSession()->has('_security_main'));
    }
}
