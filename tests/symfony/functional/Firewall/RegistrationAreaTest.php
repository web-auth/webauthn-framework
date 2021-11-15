<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Tests\Functional\Firewall;

use Cose\Algorithms;
use function Safe\base64_decode;
use function Safe\json_decode;
use function Safe\json_encode;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\Bundle\Tests\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Tests\Functional\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Tests\Functional\User;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @internal
 */
final class RegistrationAreaTest extends WebTestCase
{
    /**
     * @test
     */
    public function aRequestWithoutUsernameCannotBeProcessed(): void
    {
        $content = [
            'displayName' => 'FOO',
        ];
        $client = self::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertSame('error', $data['status']);
        static::assertSame(401, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('username: This value should not be blank.', $data['errorMessage']);
    }

    /**
     * @test
     */
    public function aRequestWithoutDisplayNameCannotBeProcessed(): void
    {
        $content = [
            'username' => 'foo',
        ];
        $client = self::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertSame('error', $data['status']);
        static::assertSame(401, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('displayName: This value should not be blank.', $data['errorMessage']);
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
        $client = self::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertSame(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('', $data['errorMessage']);

        static::assertArrayHasKey('attestation', $data);
        static::assertSame('indirect', $data['attestation']);

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertSame([
            'requireResidentKey' => true,
            'userVerification' => 'preferred',
            'authenticatorAttachment' => 'cross-platform',
        ], $data['authenticatorSelection']);
    }

    /**
     * @test
     */
    public function aValidRequestProcessedOnOtherHost(): void
    {
        $content = [
            'username' => 'foo',
            'displayName' => 'FOO',
            'authenticatorSelection' => [
                'requireResidentKey' => true,
            ],
        ];
        $client = self::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'foo.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertSame(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('', $data['errorMessage']);

        static::assertArrayHasKey('attestation', $data);
        static::assertSame('none', $data['attestation']);

        static::assertArrayHasKey('authenticatorSelection', $data);
        static::assertSame([
            'requireResidentKey' => true,
            'userVerification' => 'preferred',
        ], $data['authenticatorSelection']);
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
        $client = self::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertSame(200, $client->getResponse()->getStatusCode());
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
            'requireResidentKey' => true,
            'userVerification' => 'required',
            'authenticatorAttachment' => 'platform',
        ], $data['authenticatorSelection']);
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
        $client = self::createClient([], [
            'HTTPS' => 'on',
        ]);
        $client->request(Request::METHOD_POST, '/register/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertSame('error', $data['status']);
        static::assertSame(401, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('Invalid username', $data['errorMessage']);
    }

    /**
     * @test
     */
    public function aRegistrationResultRequestCannotBeAcceptedIfNoOptionsAreAvailableInTheStorage(): void
    {
        $content = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';

        $client = self::createClient([], [
            'HTTPS' => 'on',
        ]);
        $session = $client->getContainer()
            ->get('session')
        ;
        $session->remove('FOO_BAR_SESSION_PARAMETER');
        $session->save();

        $client->request(Request::METHOD_POST, '/register', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode($content));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertSame('error', $data['status']);
        static::assertSame(401, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('No public key credential options available for this session.', $data['errorMessage']);
    }

    /**
     * @test
     */
    public function aValidRegistrationResultRequestIsCorrectlyManaged(): void
    {
        $publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(
            64
        ), 'Test PublicKeyCredentialUserEntity');
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions
            ::create(
                new PublicKeyCredentialRpEntity('My Application'),
                $publicKeyCredentialUserEntity,
                base64_decode(
                    '9WqgpRIYvGMCUYiFT20o1U7hSD193k11zu4tKP7wRcrE26zs1zc4LHyPinvPGS86wu6bDvpwbt8Xp2bQ3VBRSQ==',
                    true
                ),
                [new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256)]
            )
        ;

        $content = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';

        $client = self::createClient([], [
            'HTTPS' => 'on',
        ]);
        $pkcsRepository = $client->getContainer()
            ->get(PublicKeyCredentialSourceRepository::class)
        ;
        $pkcsRepository->clearCredentials();
        $session = $client->getContainer()
            ->get('session')
        ;
        $session->set('FOO_BAR_SESSION_PARAMETER', [
            'options' => $publicKeyCredentialCreationOptions,
            'userEntity' => $publicKeyCredentialUserEntity,
        ]);
        $session->save();

        $client->request(Request::METHOD_POST, '/register', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'localhost',
        ], $content);
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true);

        static::assertArrayHasKey('status', $data);
        static::assertSame('ok', $data['status']);
        static::assertSame(200, $client->getResponse()->getStatusCode());
        static::assertArrayHasKey('errorMessage', $data);
        static::assertSame('', $data['errorMessage']);

        $pkueRepository = $client->getContainer()
            ->get(PublicKeyCredentialUserEntityRepository::class)
        ;
        $user = $pkueRepository->findOneByUsername('test@foo.com');
        static::assertInstanceOf(User::class, $user);

        static::assertTrue($session->has('_security_main'));
        static::assertTrue($client->getResponse()->headers->has('set-cookie'));
    }
}
