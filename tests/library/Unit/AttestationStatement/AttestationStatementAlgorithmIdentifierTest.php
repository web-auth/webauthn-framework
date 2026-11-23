<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use Closure;
use Cose\Algorithm\Manager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Clock\ClockInterface;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\Exception\AttestationStatementLoadingException;
use Webauthn\Tests\AbstractTestCase;

/**
 * The "alg" of a packed, TPM or Android Key attestation statement is a COSEAlgorithmIdentifier, an integer (WebAuthn
 * Level 3, sections 8.2, 8.3 and 8.4). The CBOR decoder normalizes an integer into its decimal string, which is
 * accepted as well; any other string would be read as the integer its cast gives.
 *
 * @internal
 */
final class AttestationStatementAlgorithmIdentifierTest extends AbstractTestCase
{
    /**
     * @param Closure(ClockInterface): AttestationStatementSupport $createSupport
     * @param array<string, mixed> $attestation
     */
    #[Test]
    #[DataProvider('statementsWhoseAlgorithmIsNotAnInteger')]
    public function aStatementWhoseAlgorithmIsNotAnIntegerIsNotLoaded(Closure $createSupport, array $attestation): void
    {
        // Then
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('The attestation statement value "alg" must be an integer.');

        // Given
        $support = $createSupport($this->clock);

        // When
        $support->load($attestation);
    }

    /**
     * @return iterable<string, array{Closure(ClockInterface): AttestationStatementSupport, array<string, mixed>}>
     */
    public static function statementsWhoseAlgorithmIsNotAnInteger(): iterable
    {
        $algorithms = [
            'a leading zero' => '-065535',
            'a trailing space' => '-65535 ',
            'a leading space' => ' -65535',
            'a decimal part' => '-65535.9',
            'trailing letters' => '-65535abc',
            'an exponent' => '-6.5535e4',
            'an integer PHP cannot hold' => '-9223372036854775809',
            'a float' => -65535.0,
            'a list' => [-65535],
        ];
        foreach ($algorithms as $name => $algorithm) {
            yield 'packed, ' . $name => [
                static fn (ClockInterface $clock): AttestationStatementSupport => PackedAttestationStatementSupport::create(
                    Manager::create()
                ),
                [
                    'fmt' => 'packed',
                    'attStmt' => [
                        'sig' => 'signature',
                        'alg' => $algorithm,
                    ],
                ],
            ];
            yield 'android-key, ' . $name => [
                static fn (ClockInterface $clock): AttestationStatementSupport => AndroidKeyAttestationStatementSupport::create(),
                [
                    'fmt' => 'android-key',
                    'attStmt' => [
                        'sig' => 'signature',
                        'x5c' => [],
                        'alg' => $algorithm,
                    ],
                ],
            ];
            yield 'tpm, ' . $name => [
                static fn (ClockInterface $clock): AttestationStatementSupport => TPMAttestationStatementSupport::create(
                    $clock
                ),
                [
                    'fmt' => 'tpm',
                    'attStmt' => [
                        'ver' => '2.0',
                        'sig' => 'signature',
                        'alg' => $algorithm,
                        'certInfo' => '',
                        'pubArea' => '',
                    ],
                ],
            ];
        }
    }

    #[Test]
    #[DataProvider('integerAlgorithms')]
    public function aStatementWhoseAlgorithmIsAnIntegerIsLoaded(int|string $algorithm): void
    {
        // Given
        $support = PackedAttestationStatementSupport::create(Manager::create());

        // When
        $statement = $support->load([
            'fmt' => 'packed',
            'attStmt' => [
                'sig' => 'signature',
                'alg' => $algorithm,
            ],
        ]);

        // Then
        static::assertSame($algorithm, $statement->get('alg'));
    }

    /**
     * @return iterable<string, array{int|string}>
     */
    public static function integerAlgorithms(): iterable
    {
        yield 'an integer' => [-7];
        yield 'the decimal string the CBOR decoder normalizes an integer into' => ['-7'];
    }
}
