<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\FullySpecified\Ed25519;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Algorithm\Signature\FullySpecified\ESP384;
use Cose\Algorithm\Signature\FullySpecified\ESP512;
use Cose\Algorithms;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The fully-specified identifiers introduced by RFC 9864 are part of the algorithms known to the verification manager,
 * even though the Relying Party keeps the legacy identifiers in "pubKeyCredParams".
 *
 * @internal
 *
 * @see https://w3c.github.io/webauthn/#sctn-alg-identifier
 */
final class CoseAlgorithmManagerTest extends WebauthnTestCase
{
    /**
     * @return iterable<string, array{int, class-string}>
     */
    public static function fullySpecifiedAlgorithms(): iterable
    {
        yield 'ESP256' => [Algorithms::COSE_ALGORITHM_ESP256, ESP256::class];

        yield 'ESP384' => [Algorithms::COSE_ALGORITHM_ESP384, ESP384::class];

        yield 'ESP512' => [Algorithms::COSE_ALGORITHM_ESP512, ESP512::class];

        yield 'Ed25519' => [Algorithms::COSE_ALGORITHM_ED25519, Ed25519::class];
    }

    #[Test]
    #[DataProvider('fullySpecifiedAlgorithms')]
    public function theFullySpecifiedAlgorithmIsAvailable(int $identifier, string $class): void
    {
        // Given
        self::bootKernel();
        $manager = self::getContainer()->get('webauthn.cose.algorithm.manager');
        static::assertInstanceOf(Manager::class, $manager);

        // When
        $algorithm = $manager->get($identifier);

        // Then
        static::assertInstanceOf($class, $algorithm);
    }
}
