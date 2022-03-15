<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Attestation;

use Cose\Algorithms;
use function count;
use InvalidArgumentException;
use const JSON_THROW_ON_ERROR;
use function Safe\base64_decode;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\CustomSessionStorage;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\Tests\Bundle\Functional\User;

/**
 * @internal
 */
final class AdditionalAuthenticatorTest extends WebTestCase
{
    private KernelBrowser $client;

    private OptionsStorage $storage;

    protected function setUp(): void
    {
        $this->client = static::createClient([], [
            'HTTPS' => 'on',
        ]);

        $this->storage = static::getContainer()->get(CustomSessionStorage::class);
    }

    /**
     * @test
     */
    public function anExistingUserCanAskForOptionsUsingTheDedicatedController(): void
    {
        $this->logIn();
        $this->client->request(Request::METHOD_POST, '/devices/add/options', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_HOST' => 'test.com',
        ], json_encode([], JSON_THROW_ON_ERROR));
        $response = $this->client->getResponse();
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
            'timeout',
        ];
        foreach ($expectedKeys as $expectedKey) {
            static::assertArrayHasKey($expectedKey, $data);
        }
        static::assertSame('ok', $data['status']);
    }

    /**
     * @test
     */
    public function withTheOptionAnExistingUserCanRegisterNewAnotherAuthenticator(): void
    {
        /** @var PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository */
        $publicKeyCredentialSourceRepository = self::$kernel
            ->getContainer()
            ->get(PublicKeyCredentialSourceRepository::class)
        ;
        $this->logIn();

        /** @var PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions */
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

        $this->storage->store(Item::create(
            $publicKeyCredentialCreationOptions,
            $publicKeyCredentialCreationOptions->getUser()
        ));

        $numberOfRegisteredCredentials = count(
            $publicKeyCredentialSourceRepository->findAllForUserEntity($publicKeyCredentialCreationOptions->getUser())
        );
        $body = '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}';
        $this->client->request(
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
        $response = $this->client->getResponse();
        $data = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        static::assertSame(201, $response->getStatusCode());
        static::assertIsArray($data);
        $expectedKeys = ['status', 'errorMessage'];
        foreach ($expectedKeys as $expectedKey) {
            static::assertArrayHasKey($expectedKey, $data);
        }
        static::assertSame('ok', $data['status']);

        $newNumberOfRegisteredCredentials = count(
            $publicKeyCredentialSourceRepository->findAllForUserEntity($publicKeyCredentialCreationOptions->getUser())
        );
        static::assertSame($numberOfRegisteredCredentials + 1, $newNumberOfRegisteredCredentials);
    }

    private function logIn(): void
    {
        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"EhNVt3T8V12FJvSAc50nhKnZ-MEc-kf84xepDcGyN1g","attestation":"direct","user":{"name":"XY5nn3p_6olTLjoB2Jbb","id":"OTI5ZmJhMmYtMjM2MS00YmM2LWE5MTctYmI3NmFhMTRjN2Y5","displayName":"Bennie Moneypenny"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        /** @var PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions */
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        $user = new User(
            $publicKeyCredentialCreationOptions->getUser()
                ->getName(),
            $publicKeyCredentialCreationOptions->getUser()
                ->getId(),
            $publicKeyCredentialCreationOptions->getUser()
                ->getDisplayName(),
            null,
            ['ROLE_ADMIN', 'ROLE_USER']
        );

        $firewallName = 'main';
        $firewallContext = 'main';

        $token = new WebauthnToken(
            $user,
            $publicKeyCredentialCreationOptions,
            new PublicKeyCredentialDescriptor(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, '0123456789'),
            true,
            false,
            0,
            0,
            100,
            null,
            $firewallName,
            $user->getRoles()
        );
        $token->setUser($user);

        $container = static::getContainer();
        $container->get('security.untracked_token_storage')
            ->setToken($token)
        ;

        if (! $container->has('session.factory')) {
            throw new InvalidArgumentException('No session factory');
        }

        $session = $container->get('session.factory')
            ->createSession()
        ;
        $session->set('_security_' . $firewallContext, serialize($token));
        $session->save();

        $domains = array_unique(array_map(static function (Cookie $cookie) use ($session) {
            return $cookie->getName() === $session->getName() ? $cookie->getDomain() : '';
        }, $this->client->getCookieJar()
            ->all())) ?: [''];
        foreach ($domains as $domain) {
            $cookie = new Cookie($session->getName(), $session->getId(), null, null, $domain);
            $this->client->getCookieJar()
                ->set($cookie)
            ;
        }
    }
}
