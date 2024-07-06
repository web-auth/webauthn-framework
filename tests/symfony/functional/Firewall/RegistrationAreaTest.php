<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use Cose\Algorithms;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\CustomSessionStorage;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialUserEntityRepository;
use Webauthn\Tests\Bundle\Functional\User;
use function base64_decode;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class RegistrationAreaTest extends WebTestCase
{
    #[Test]
    public function aRequestWithoutUsernameCanBeProcessed(): void
    {
        $content = [
            'displayName' => 'FOO',
        ];
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/api/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertResponseStatusCodeSame(200);
    }

    #[Test]
    public function aRequestWithoutDisplayNameCanBeProcessed(): void
    {
        $content = [
            'username' => 'foo',
        ];
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/api/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertResponseStatusCodeSame(200);
    }

    #[Test]
    public function aValidRequestProcessed(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 'FOO',
            'authenticatorSelection' => [
                'authenticatorAttachment' => 'cross-platform',
                'userVerification' => 'required',
                'requireResidentKey' => true,
            ],
            'attestation' => 'indirect',
        ];
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/api/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertResponseIsSuccessful();
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('', $data['errorMessage']);

        static::assertArrayHasKey('attestation', $data);
        static::assertSame('indirect', $data['attestation']);

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertSame([
            'authenticatorAttachment' => 'cross-platform',
            'requireResidentKey' => true,
            'userVerification' => 'required',
            'residentKey' => 'required',
        ], $data['authenticatorSelection']);
    }

    #[Test]
    public function aValidRequestProcessedOnOtherHost(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 'FOO',
            'authenticatorSelection' => [
                'requireResidentKey' => true,
            ],
        ];
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/api/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'foo.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertResponseIsSuccessful();
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('', $data['errorMessage']);

        static::assertArrayHasKey('attestation', $data);
        static::assertSame('none', $data['attestation']);

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertSame([
            'requireResidentKey' => true,
            'userVerification' => 'preferred',
            'residentKey' => 'required',
        ], $data['authenticatorSelection']);
    }

    #[Test]
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
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/api/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertResponseIsSuccessful();
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('', $data['errorMessage']);

        static::assertArrayHasKey('attestation', $data);
        static::assertSame('none', $data['attestation']);
        static::assertSame([
            'loc' => true,
            'def' => '123',
        ], $data['extensions']);

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertSame([
            'authenticatorAttachment' => 'platform',
            'requireResidentKey' => true,
            'userVerification' => 'required',
            'residentKey' => 'required',
        ], $data['authenticatorSelection']);
    }

    #[Test]
    public function aRegistrationOptionsRequestCanBeAcceptedForExistingUsers(): void
    {
        $content = [
            'username' => 'admin',
            'displayName' => 'Admin',
        ];
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/api/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertResponseIsSuccessful();
    }

    #[Test]
    public function aRegistrationResultRequestCannotBeAcceptedIfNoOptionsAreAvailableInTheStorage(): void
    {
        $content = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';

        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/api/register', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], $content);
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertArrayHasKey('status', $data);
        static::assertSame('error', $data['status']);
        self::assertResponseStatusCodeSame(401);
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('No public key credential options available for this session.', $data['errorMessage']);
    }

    #[Test]
    public function aValidRegistrationResultRequestIsCorrectlyManaged(): void
    {
        $publicKeyCredentialUserEntity = PublicKeyCredentialUserEntity::create('test@foo.com', random_bytes(
            64
        ), 'Test PublicKeyCredentialUserEntity');
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions
            ::create(
                PublicKeyCredentialRpEntity::create('My Application'),
                $publicKeyCredentialUserEntity,
                base64_decode(
                    '9WqgpRIYvGMCUYiFT20o1U7hSD193k11zu4tKP7wRcrE26zs1zc4LHyPinvPGS86wu6bDvpwbt8Xp2bQ3VBRSQ==',
                    true
                ),
                [PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_ES256)]
            );

        $content = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';

        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $pkcsRepository = $client->getContainer()
            ->get(PublicKeyCredentialSourceRepository::class);
        $pkcsRepository->clearCredentials();

        $storage = static::getContainer()->get(CustomSessionStorage::class);
        $storage->store(Item::create($publicKeyCredentialCreationOptions, $publicKeyCredentialUserEntity));

        $client->request(Request::METHOD_POST, '/api/register', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], $content);
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertResponseIsSuccessful();
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('', $data['errorMessage']);

        $pkueRepository = $client->getContainer()
            ->get(PublicKeyCredentialUserEntityRepository::class);
        $user = $pkueRepository->findOneByUsername('test@foo.com');
        static::assertInstanceOf(User::class, $user);

        static::assertTrue($client->getRequest()->getSession()->has('_security_main'));
        static::assertTrue($client->getResponse()->headers->has('set-cookie'));
    }
}
