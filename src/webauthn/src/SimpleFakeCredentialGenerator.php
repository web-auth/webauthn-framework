<?php

declare(strict_types=1);

namespace Webauthn;

use function count;
use function ord;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\HttpFoundation\Request;
use function trigger_deprecation;

/**
 * Generates a stable list of decoy credentials for a username, so that the assertion options of an unknown username
 * look like the ones of a registered account.
 *
 * Each decoy takes the shape of a credential that real authenticators produce: the length of its credential ID and its
 * transports come from a list of shapes, and its ID is derived from the username and the secret. The default shapes
 * follow synced platform passkeys (20-byte IDs, hybrid and internal transports), Windows Hello (32 bytes, internal) and
 * security keys (64 bytes, USB with or without NFC, or no transports when the client did not report them). An
 * application whose users register other authenticators should pass the shapes found in its own credential records,
 * and a UsernameNormalizer when its user entity repository does not compare usernames byte for byte.
 *
 * The decoys remain a best effort: the response time or the number of credentials can still differ from a registered
 * account, and only usernameless authentication fully hides whether an account exists.
 */
final readonly class SimpleFakeCredentialGenerator implements FakeCredentialGenerator
{
    /**
     * @var list<FakeCredentialShape>
     */
    private array $shapes;

    /**
     * @param FakeCredentialShape[] $shapes
     */
    public function __construct(
        private null|CacheItemPoolInterface $cache = null,
        private string $secret = '',
        private null|UsernameNormalizer $usernameNormalizer = null,
        array $shapes = [],
    ) {
        if ($secret === '') {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '5.3.5',
                'Instantiating "%s" without a secret is deprecated since 5.3.5 and a non-empty secret will be required in 6.0.0. With an empty secret the generated fake credentials depend only on the username and become predictable, which lets an unauthenticated requester tell fake responses from real ones and defeats the username enumeration protection. Provide a non-empty secret, for example the application secret.',
                self::class
            );
        }
        $this->shapes = $shapes === [] ? self::defaultShapes() : array_values($shapes);
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    public function generate(Request $request, string $username): array
    {
        $username = $this->usernameNormalizer?->normalize($username) ?? $username;
        if ($this->cache === null) {
            return $this->generateCredentials($username);
        }

        $cacheKey = 'fake_credentials_v3_' . hash('xxh128', $username);
        $cacheItem = $this->cache->getItem($cacheKey);
        if ($cacheItem->isHit()) {
            /** @var PublicKeyCredentialDescriptor[] */
            return $cacheItem->get();
        }

        $credentials = $this->generateCredentials($username);
        $cacheItem->set($credentials);
        $this->cache->save($cacheItem);

        return $credentials;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function generateCredentials(string $username): array
    {
        $seed = hash('sha256', $username . $this->secret, true);
        $count = (ord($seed[0]) % 3) + 1;

        $credentials = [];
        for ($i = 0; $i < $count; $i++) {
            $credSeed = hash('sha256', $seed . pack('N', $i), true);
            $shape = $this->shapes[ord($credSeed[0]) % count($this->shapes)];
            $credentials[] = PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                hash_hkdf('sha256', $credSeed, $shape->credentialIdLength, 'fake credential ID'),
                $shape->transports
            );
        }

        return $credentials;
    }

    /**
     * Shapes observed on registration responses of real authenticators, the test fixtures of this repository included:
     * Apple platform passkeys, Windows Hello, and security keys such as the YubiKey 5 or U2F keys.
     *
     * @return list<FakeCredentialShape>
     */
    private static function defaultShapes(): array
    {
        return [
            FakeCredentialShape::create(20, [
                PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_HYBRID,
                PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_INTERNAL,
            ]),
            FakeCredentialShape::create(32, [PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_INTERNAL]),
            FakeCredentialShape::create(64, [
                PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_NFC,
                PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_USB,
            ]),
            FakeCredentialShape::create(64, [PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_USB]),
            FakeCredentialShape::create(64),
        ];
    }
}
