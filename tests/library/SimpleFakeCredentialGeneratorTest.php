<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use function count;
use const E_USER_DEPRECATED;
use const JSON_THROW_ON_ERROR;
use function ord;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function strlen;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\FakeCredentialShape;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\SimpleFakeCredentialGenerator;
use Webauthn\UsernameNormalizer;

/**
 * @internal
 */
final class SimpleFakeCredentialGeneratorTest extends TestCase
{
    #[Test]
    public function theGeneratedListIsDeterministicForTheSameUsernameAndSecret(): void
    {
        $generator = new SimpleFakeCredentialGenerator(null, 'a-deployment-secret');
        $request = Request::create('https://example.com');

        $first = $generator->generate($request, 'alice@example.com');
        $second = $generator->generate($request, 'alice@example.com');

        static::assertNotEmpty($first);
        static::assertContainsOnlyInstancesOf(PublicKeyCredentialDescriptor::class, $first);
        static::assertEquals($first, $second);
    }

    #[Test]
    public function differentUsernamesProduceDifferentLists(): void
    {
        $generator = new SimpleFakeCredentialGenerator(null, 'a-deployment-secret');
        $request = Request::create('https://example.com');

        $alice = $generator->generate($request, 'alice@example.com');
        $bob = $generator->generate($request, 'bob@example.com');

        static::assertNotEquals($alice, $bob);
    }

    /**
     * Security non-regression for GHSA-8gvp-8vj9-p3q7: authenticators return credential IDs as raw
     * bytes. A fake ID spelled as a hex string stands out once the allowCredentials entries are
     * base64url decoded, whatever the secret, and tells an unknown username from a registered one.
     */
    #[Test]
    public function fakeCredentialIdsAreRawBytesAndNotHexStrings(): void
    {
        $generator = new SimpleFakeCredentialGenerator(null, 'a-deployment-secret');
        $request = Request::create('https://example.com');

        $descriptors = $generator->generate($request, 'alice@example.com');

        static::assertNotEmpty($descriptors);
        foreach ($descriptors as $descriptor) {
            static::assertContains(strlen($descriptor->id), [20, 32, 64]);
            static::assertFalse(ctype_xdigit($descriptor->id), 'A fake credential ID must not be a hex string.');
        }
    }

    /**
     * Security non-regression for GHSA-8gvp-8vj9-p3q7: a decoy that always had a 32-byte ID and
     * transports drawn at random (smart-card or BLE, lists out of lexicographic order, never empty)
     * stood apart from the credentials that real authenticators produce. Every decoy now takes one
     * of the shapes of a real credential, and every default shape is used.
     */
    #[Test]
    public function everyDecoyTakesTheShapeOfARealCredential(): void
    {
        $generator = new SimpleFakeCredentialGenerator(null, 'a-deployment-secret');
        $request = Request::create('https://example.com');
        $occurrences = [
            '20:["hybrid","internal"]' => 0,
            '32:["internal"]' => 0,
            '64:["nfc","usb"]' => 0,
            '64:["usb"]' => 0,
            '64:[]' => 0,
        ];

        for ($i = 0; $i < 200; $i++) {
            foreach ($generator->generate($request, sprintf('user%d@example.com', $i)) as $descriptor) {
                $shape = strlen($descriptor->id) . ':' . json_encode($descriptor->transports, JSON_THROW_ON_ERROR);
                static::assertArrayHasKey($shape, $occurrences, 'A decoy must take the shape of a real credential.');
                ++$occurrences[$shape];
            }
        }

        static::assertNotContains(0, $occurrences, 'Every default shape must be used.');
    }

    #[Test]
    public function theShapesGivenToTheGeneratorReplaceTheDefaultOnes(): void
    {
        $generator = new SimpleFakeCredentialGenerator(null, 'a-deployment-secret', null, [
            FakeCredentialShape::create(48, ['usb', 'nfc']),
        ]);
        $request = Request::create('https://example.com');

        for ($i = 0; $i < 50; $i++) {
            foreach ($generator->generate($request, sprintf('user%d@example.com', $i)) as $descriptor) {
                static::assertSame(48, strlen($descriptor->id));
                static::assertSame(['nfc', 'usb'], $descriptor->transports);
            }
        }
    }

    /**
     * Security non-regression for GHSA-8gvp-8vj9-p3q7: when the user entity repository finds an
     * account whatever the case of its username, two spellings of a registered username get the
     * same credentials. Two spellings of an unknown username must then get the same decoys,
     * otherwise comparing them reveals which usernames are registered.
     */
    #[Test]
    public function twoSpellingsThatTheNormalizerMergesGetTheSameDecoys(): void
    {
        $normalizer = new class() implements UsernameNormalizer {
            public function normalize(string $username): string
            {
                return mb_strtolower($username);
            }
        };
        $request = Request::create('https://example.com');
        $withoutNormalizer = new SimpleFakeCredentialGenerator(null, 'a-deployment-secret');
        $withNormalizer = new SimpleFakeCredentialGenerator(new ArrayAdapter(), 'a-deployment-secret', $normalizer);

        static::assertNotEquals(
            $withoutNormalizer->generate($request, 'alice@example.com'),
            $withoutNormalizer->generate($request, 'Alice@Example.com')
        );
        static::assertEquals(
            $withNormalizer->generate($request, 'alice@example.com'),
            $withNormalizer->generate($request, 'Alice@Example.com')
        );
        static::assertEquals(
            $withoutNormalizer->generate($request, 'alice@example.com'),
            $withNormalizer->generate($request, 'Alice@Example.com')
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function listsCachedByAffectedVersions(): iterable
    {
        yield 'hex IDs, up to 5.3.9' => ['fake_credentials_', hash('sha256', 'alice@example.com')];
        yield '32-byte IDs, from 5.3.10 to 5.3.12' => [
            'fake_credentials_v2_',
            hash('sha256', 'alice@example.com', true),
        ];
    }

    /**
     * Lists cached by the versions affected by GHSA-8gvp-8vj9-p3q7 are stored without expiration:
     * they must not be served anymore once the generator emits decoys shaped like real credentials.
     */
    #[Test]
    #[DataProvider('listsCachedByAffectedVersions')]
    public function aListCachedByAnAffectedVersionIsNotServed(string $cacheKeyPrefix, string $legacyId): void
    {
        $username = 'alice@example.com';
        $request = Request::create('https://example.com');
        $cache = new ArrayAdapter();
        $legacyItem = $cache->getItem($cacheKeyPrefix . hash('xxh128', $username));
        $legacyItem->set([
            PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $legacyId,
                [PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_SMART_CARD]
            ),
        ]);
        $cache->save($legacyItem);

        $withCache = new SimpleFakeCredentialGenerator($cache, 'a-deployment-secret');
        $withoutCache = new SimpleFakeCredentialGenerator(null, 'a-deployment-secret');

        static::assertEquals(
            $withoutCache->generate($request, $username),
            $withCache->generate($request, $username)
        );
    }

    /**
     * Security non-regression for GHSA-gq4g-fpc9-vjfq: the secret must take part in the seed. An
     * attacker who only knows the username (and therefore assumes the empty default secret) must
     * not be able to reproduce the server output. If a future change drops the secret from the
     * derivation, the two lists collapse and this test fails.
     */
    #[Test]
    public function aNonEmptySecretMakesTheListUnpredictableFromTheUsernameAlone(): void
    {
        $request = Request::create('https://example.com');
        $username = 'alice@example.com';

        $withSecret = new SimpleFakeCredentialGenerator(null, 'a-deployment-secret');
        $serverList = $this->asArrays($withSecret->generate($request, $username));

        $attackerList = $this->recomputeAssumingEmptySecret($username);

        static::assertNotEquals(
            $attackerList,
            $serverList,
            'A non-empty secret must prevent the list from being reproducible from the username alone.'
        );
    }

    /**
     * Documents the vulnerable behaviour the fix warns about: with an empty secret the list is
     * fully predictable from the public username. Kept as a guard so the relationship between the
     * secret and the output stays explicit.
     */
    #[Test]
    #[Group('legacy')]
    public function anEmptySecretMakesTheListReproducibleFromTheUsernameAlone(): void
    {
        $request = Request::create('https://example.com');
        $username = 'alice@example.com';

        $generator = $this->withSuppressedDeprecations(
            static fn (): SimpleFakeCredentialGenerator => new SimpleFakeCredentialGenerator()
        );
        $serverList = $this->asArrays($generator->generate($request, $username));

        $attackerList = $this->recomputeAssumingEmptySecret($username);

        static::assertEquals($attackerList, $serverList);
    }

    #[Test]
    #[Group('legacy')]
    public function itTriggersADeprecationWhenInstantiatedWithoutASecret(): void
    {
        $messages = [];
        set_error_handler(static function (int $type, string $message) use (&$messages): bool {
            $messages[] = $message;

            return true;
        }, E_USER_DEPRECATED);

        try {
            new SimpleFakeCredentialGenerator();
        } finally {
            restore_error_handler();
        }

        static::assertCount(1, $messages);
        static::assertStringContainsString('without a secret is deprecated', $messages[0]);
    }

    #[Test]
    public function itDoesNotTriggerADeprecationWhenInstantiatedWithASecret(): void
    {
        $messages = [];
        set_error_handler(static function (int $type, string $message) use (&$messages): bool {
            $messages[] = $message;

            return true;
        }, E_USER_DEPRECATED);

        try {
            new SimpleFakeCredentialGenerator(null, 'a-deployment-secret');
        } finally {
            restore_error_handler();
        }

        static::assertSame([], $messages);
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $descriptors
     *
     * @return array<int, array{type: string, id: string, transports: string[]}>
     */
    private function asArrays(array $descriptors): array
    {
        return array_map(
            static fn (PublicKeyCredentialDescriptor $descriptor): array => [
                'type' => $descriptor->type,
                'id' => $descriptor->id,
                'transports' => $descriptor->transports,
            ],
            $descriptors
        );
    }

    /**
     * Re-implements the generation algorithm as a network attacker would, knowing only the
     * username and assuming the empty default secret.
     *
     * @return array<int, array{type: string, id: string, transports: string[]}>
     */
    private function recomputeAssumingEmptySecret(string $username): array
    {
        $shapes = [
            [20, ['hybrid', 'internal']],
            [32, ['internal']],
            [64, ['nfc', 'usb']],
            [64, ['usb']],
            [64, []],
        ];
        $seed = hash('sha256', $username . '', true);
        $credentialCount = (ord($seed[0]) % 3) + 1;

        $credentials = [];
        for ($i = 0; $i < $credentialCount; $i++) {
            $credentialSeed = hash('sha256', $seed . pack('N', $i), true);
            [$length, $transports] = $shapes[ord($credentialSeed[0]) % count($shapes)];
            $credentials[] = [
                'type' => PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                'id' => hash_hkdf('sha256', $credentialSeed, $length, 'fake credential ID'),
                'transports' => $transports,
            ];
        }

        return $credentials;
    }

    /**
     * @param callable():SimpleFakeCredentialGenerator $factory
     */
    private function withSuppressedDeprecations(callable $factory): SimpleFakeCredentialGenerator
    {
        set_error_handler(static fn (): bool => true, E_USER_DEPRECATED);

        try {
            return $factory();
        } finally {
            restore_error_handler();
        }
    }
}
