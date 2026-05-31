<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use function count;
use const E_USER_DEPRECATED;
use function ord;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\SimpleFakeCredentialGenerator;

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
        $serverList = $this->shape($withSecret->generate($request, $username));

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
        $serverList = $this->shape($generator->generate($request, $username));

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
    private function shape(array $descriptors): array
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
        $transports = [
            PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_USB,
            PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_NFC,
            PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_BLE,
            PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_HYBRID,
            PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_INTERNAL,
            PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_SMART_CARD,
        ];
        $seed = hash('sha256', $username . '', true);
        $credentialCount = (ord($seed[0]) % 3) + 1;

        $credentials = [];
        for ($i = 0; $i < $credentialCount; $i++) {
            $credentialSeed = hash('sha256', $seed . pack('N', $i), true);
            $transportCount = (ord($credentialSeed[0]) % 2) + 1;
            $selectedTransports = [];
            for ($j = 0; $j < $transportCount; $j++) {
                $selectedTransports[] = $transports[ord($credentialSeed[$j + 1]) % count($transports)];
            }
            $credentials[] = [
                'type' => PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                'id' => hash('sha256', $credentialSeed . $username),
                'transports' => array_values(array_unique($selectedTransports)),
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
