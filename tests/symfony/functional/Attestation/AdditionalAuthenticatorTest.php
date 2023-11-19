<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Attestation;

use Cose\Algorithms;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\CustomSessionStorage;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\Tests\Bundle\Functional\User;
use function assert;
use function base64_decode;
use function count;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class AdditionalAuthenticatorTest extends WebTestCase
{
    #[Test]
    public function anExistingUserCanAskForOptionsUsingTheDedicatedController(): void
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $this->logIn($client);
        $client->request(Request::METHOD_POST, '/devices/add/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode([], JSON_THROW_ON_ERROR));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertResponseIsSuccessful();
        static::assertIsArray($data);
        $expectedKeys = [
            'status',
            'errorMessage',
            'rp',
            'pubKeyCredParams',
            'challenge',
            'attestation',
            'user',
            'authenticatorSelection',
        ];
        foreach ($expectedKeys as $expectedKey) {
            static::assertArrayHasKey($expectedKey, $data);
        }
        static::assertSame('ok', $data['status']);
    }

    #[Test]
    public function thePublicKeyCredentialDataCanBeLoaded(): void
    {
        $data = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';
        $serializer = static::getContainer()->get(SerializerInterface::class);
        assert($serializer instanceof SerializerInterface);
        $publicKeyCredential = $serializer->deserialize($data, PublicKeyCredential::class, 'json');

        static::assertInstanceOf(PublicKeyCredential::class, $publicKeyCredential);
    }

    #[Test]
    #[Depends('thePublicKeyCredentialDataCanBeLoaded')]
    public function withTheOptionAnExistingUserCanRegisterNewAnotherAuthenticator(): void
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        /** @var PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository */
        $publicKeyCredentialSourceRepository = $client->getContainer()
            ->get(PublicKeyCredentialSourceRepository::class);
        $this->logIn($client);

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

        $storage = static::getContainer()->get(CustomSessionStorage::class);
        $storage->store(Item::create(
            $publicKeyCredentialCreationOptions,
            $publicKeyCredentialCreationOptions->user
        ));
        $publicKeyCredentialSourceRepository->removeCredentialWithId(
            'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK'
        );

        $numberOfRegisteredCredentials = count(
            $publicKeyCredentialSourceRepository->findAllForUserEntity($publicKeyCredentialCreationOptions->user)
        );
        $body = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';
        $client->request(
            Request::METHOD_POST,
            '/devices/add',
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_HOST' => 'localhost',
            ],
            $body
        );
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertResponseStatusCodeSame(201);
        static::assertIsArray($data);
        $expectedKeys = ['status', 'errorMessage'];
        foreach ($expectedKeys as $expectedKey) {
            static::assertArrayHasKey($expectedKey, $data);
        }
        static::assertSame('ok', $data['status']);

        $newNumberOfRegisteredCredentials = count(
            $publicKeyCredentialSourceRepository->findAllForUserEntity($publicKeyCredentialCreationOptions->user)
        );
        static::assertSame($numberOfRegisteredCredentials + 1, $newNumberOfRegisteredCredentials);
    }

    #[Test]
    public function anExistingUserCanGetOptionsTestItsAuthenticators(): void
    {
        $client = static::createClient([], [
            'HTTPS' => 'on',
        ]);
        $this->logIn($client);
        $client->request(Request::METHOD_POST, '/devices/test/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode([], JSON_THROW_ON_ERROR));
        $response = $client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertResponseIsSuccessful();
        static::assertIsArray($data);
        $expectedKeys = ['status', 'errorMessage', 'rpId', 'userVerification', 'challenge'];
        foreach ($expectedKeys as $expectedKey) {
            static::assertArrayHasKey($expectedKey, $data);
        }
        static::assertSame('ok', $data['status']);
    }

    private function logIn(KernelBrowser $client): void
    {
        /** @var SerializerInterface $serializer */
        $serializer = static::getContainer()->get(SerializerInterface::class);
        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"EhNVt3T8V12FJvSAc50nhKnZ-MEc-kf84xepDcGyN1g","attestation":"direct","user":{"name":"XY5nn3p_6olTLjoB2Jbb","id":"OTI5ZmJhMmYtMjM2MS00YmM2LWE5MTctYmI3NmFhMTRjN2Y5","displayName":"Bennie Moneypenny"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        $publicKeyCredentialCreationOptions = $serializer->deserialize(
            $options,
            PublicKeyCredentialCreationOptions::class,
            'json'
        );
        $user = User::create(
            $publicKeyCredentialCreationOptions->user
                ->name,
            $publicKeyCredentialCreationOptions->user
                ->id,
            $publicKeyCredentialCreationOptions->user
                ->displayName,
            null,
            ['ROLE_ADMIN', 'ROLE_USER']
        );

        $firewallName = 'main';

        $token = new WebauthnToken(
            $user,
            $publicKeyCredentialCreationOptions,
            PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                '0123456789'
            ),
            true,
            false,
            0,
            0,
            100,
            null,
            $firewallName,
            $user->getRoles(),
            true,
            true
        );
        $token->setUser($user);

        $container = static::getContainer();
        $container->get('security.untracked_token_storage')
            ->setToken($token);

        if (! $container->has('session.factory')) {
            throw new InvalidArgumentException('No session factory');
        }

        $session = $container->get('session.factory')
            ->createSession();
        $session->set('_security_' . $firewallName, serialize($token));
        $session->save();

        $domains = array_unique(
            array_map(
                static fn (Cookie $cookie) => $cookie->getName() === $session->getName() ? $cookie->getDomain() : '',
                $client->getCookieJar()
                    ->all()
            )
        ) ?: [''];
        foreach ($domains as $domain) {
            $cookie = new Cookie($session->getName(), $session->getId(), null, null, $domain);
            $client->getCookieJar()
                ->set($cookie);
        }
    }
}
