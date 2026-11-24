<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpClient\MockHttpClient;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Event\CompromisedAuthenticatorDetected;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\Service\LocalResourceMetadataService;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;
use Webauthn\MetadataService\Statement\StatusReport;
use Webauthn\MetadataService\StatusReportRepository as StatusReportRepositoryInterface;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * The status reports of an authenticator model decide its registration wherever the flagging report sits in the
 * list, unless the application admits the flagged model (issue #1002). Metadata support is enabled, a direct
 * attestation is requested, and the registration is the packed one of a Security Key by Yubico recorded in
 * PackedAttestationStatementTest.
 *
 * @internal
 */
final class CompromisedAuthenticatorStatusReportTest extends TestCase
{
    private const YUBICO_SECURITY_KEY_AAGUID = 'f8a011f3-8c0a-4d15-8006-17111f9edc7d';

    /**
     * @return iterable<string, array{StatusReport[]}>
     */
    public static function flaggedStatusReports(): iterable
    {
        yield 'compromise reported last' => [[
            self::report(AuthenticatorStatus::FIDO_CERTIFIED, '2019-01-01'),
            self::report(AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE, '2024-06-01'),
        ]];
        yield 'compromise reported first' => [[
            self::report(AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE, '2024-06-01'),
            self::report(AuthenticatorStatus::FIDO_CERTIFIED, '2019-01-01'),
        ]];
        yield 'compromise followed by an update' => [[
            self::report(AuthenticatorStatus::FIDO_CERTIFIED, '2019-01-01'),
            self::report(AuthenticatorStatus::USER_VERIFICATION_BYPASS, '2024-06-01'),
            self::report(AuthenticatorStatus::UPDATE_AVAILABLE, '2024-07-01'),
        ]];
        yield 'user key remote compromise' => [[
            self::report(AuthenticatorStatus::USER_KEY_REMOTE_COMPROMISE, '2024-06-01'),
        ]];
        yield 'user key physical compromise' => [[
            self::report(AuthenticatorStatus::USER_KEY_PHYSICAL_COMPROMISE, '2024-06-01'),
        ]];
        yield 'revoked' => [[self::report(AuthenticatorStatus::REVOKED, '2024-06-01')]];
        yield 'revoked, newest first as in the FIDO metadata BLOB' => [[
            self::report(AuthenticatorStatus::REVOKED, '2023-12-20'),
            self::report(AuthenticatorStatus::NOT_FIDO_CERTIFIED, '2023-11-07'),
        ]];
    }

    /**
     * @return iterable<string, array{StatusReport[]}>
     */
    public static function statusReportsInGoodStanding(): iterable
    {
        yield 'no status report' => [[]];
        yield 'certified, newest first as in the FIDO metadata BLOB' => [[
            self::report(AuthenticatorStatus::FIDO_CERTIFIED_L1, '2020-01-01'),
            self::report(AuthenticatorStatus::FIDO_CERTIFIED, '2019-01-01'),
        ]];
        yield 'not certified' => [[self::report(AuthenticatorStatus::NOT_FIDO_CERTIFIED, '2019-01-01')]];
        yield 'update available' => [[
            self::report(AuthenticatorStatus::FIDO_CERTIFIED, '2019-01-01'),
            self::report(AuthenticatorStatus::UPDATE_AVAILABLE, '2024-07-01'),
        ]];
    }

    /**
     * @param StatusReport[] $statusReports
     */
    #[Test]
    #[DataProvider('flaggedStatusReports')]
    public function aFlaggedAuthenticatorModelCannotRegister(array $statusReports): void
    {
        $validator = self::validatorWithStatusReports($statusReports);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('The authenticator is compromised and cannot be used');

        $validator->check(self::registrationFromYubicoSecurityKey()->response, self::creationOptions(), 'localhost');
    }

    /**
     * @param StatusReport[] $statusReports
     */
    #[Test]
    #[DataProvider('statusReportsInGoodStanding')]
    public function anAuthenticatorModelInGoodStandingCanRegister(array $statusReports): void
    {
        $credentialRecord = self::validatorWithStatusReports($statusReports)->check(
            self::registrationFromYubicoSecurityKey()->response,
            self::creationOptions(),
            'localhost'
        );

        static::assertSame(self::YUBICO_SECURITY_KEY_AAGUID, $credentialRecord->aaguid->toRfc4122());
    }

    /**
     * @param StatusReport[] $statusReports
     */
    #[Test]
    #[DataProvider('flaggedStatusReports')]
    public function theApplicationCanAdmitAFlaggedAuthenticatorModel(array $statusReports): void
    {
        $decisions = [];
        $eventDispatcher = self::eventDispatcher($decisions, true);

        $credentialRecord = self::validatorWithStatusReports($statusReports, $eventDispatcher)->check(
            self::registrationFromYubicoSecurityKey()->response,
            self::creationOptions(),
            'localhost'
        );

        static::assertCount(1, $decisions);
        static::assertSame($credentialRecord, $decisions[0]->credentialRecord);
        static::assertSame($statusReports, $decisions[0]->statusReports);
        static::assertNotSame([], $decisions[0]->compromisedStatusReports());
    }

    /**
     * @param StatusReport[] $statusReports
     */
    #[Test]
    #[DataProvider('flaggedStatusReports')]
    public function aFlaggedAuthenticatorModelCannotRegisterWhenTheApplicationDoesNotAdmitIt(array $statusReports): void
    {
        $decisions = [];
        $validator = self::validatorWithStatusReports($statusReports, self::eventDispatcher($decisions, false));

        try {
            $validator->check(self::registrationFromYubicoSecurityKey()->response, self::creationOptions(), 'localhost');
            static::fail('The flagged authenticator model should have been refused.');
        } catch (AuthenticatorResponseVerificationException $exception) {
            static::assertSame('The authenticator is compromised and cannot be used', $exception->getMessage());
        }
        static::assertCount(1, $decisions);
    }

    /**
     * @param StatusReport[] $statusReports
     */
    #[Test]
    #[DataProvider('statusReportsInGoodStanding')]
    public function theApplicationIsNotAskedAboutAnAuthenticatorModelInGoodStanding(array $statusReports): void
    {
        $decisions = [];

        self::validatorWithStatusReports($statusReports, self::eventDispatcher($decisions, false))->check(
            self::registrationFromYubicoSecurityKey()->response,
            self::creationOptions(),
            'localhost'
        );

        static::assertSame([], $decisions);
    }

    /**
     * @param CompromisedAuthenticatorDetected[] $decisions
     */
    private static function eventDispatcher(array &$decisions, bool $admit): EventDispatcherInterface
    {
        $eventDispatcher = new EventDispatcher();
        $eventDispatcher->addListener(
            CompromisedAuthenticatorDetected::class,
            static function (CompromisedAuthenticatorDetected $event) use (&$decisions, $admit): void {
                if ($admit) {
                    $event->admit();
                }
                $decisions[] = $event;
            }
        );

        return $eventDispatcher;
    }

    private static function report(string $status, string $effectiveDate): StatusReport
    {
        return StatusReport::create($status, $effectiveDate, null, null, null, null, null, null);
    }

    /**
     * @param StatusReport[] $statusReports
     */
    private static function validatorWithStatusReports(
        array $statusReports,
        ?EventDispatcherInterface $eventDispatcher = null
    ): AuthenticatorAttestationResponseValidator {
        $statusReportRepository = new class([
            self::YUBICO_SECURITY_KEY_AAGUID => $statusReports,
        ]) implements StatusReportRepositoryInterface {
            /**
             * @param array<string, StatusReport[]> $statusReportsByAaguid
             */
            public function __construct(
                private readonly array $statusReportsByAaguid
            ) {
            }

            public function findStatusReportsByAAGUID(string $aaguid): array
            {
                return $this->statusReportsByAaguid[$aaguid] ?? [];
            }
        };

        $factory = new CeremonyStepManagerFactory();
        $factory->setAlgorithmManager(Manager::create()->add(ES256::create()));
        $factory->setAttestationStatementSupportManager(self::attestationStatementSupportManager());
        $factory->setAllowedOrigins(['https://localhost:8443']);
        $factory->enableMetadataStatementSupport(
            new MetadataStatementRepository(
                LocalResourceMetadataService::create(__DIR__ . '/../../metadataStatements/yubikey.json')
            ),
            $statusReportRepository,
            PhpCertificateChainValidator::create(new MockHttpClient())
        );
        if ($eventDispatcher !== null) {
            $factory->setEventDispatcher($eventDispatcher);
        }

        return AuthenticatorAttestationResponseValidator::create($factory->creationCeremony());
    }

    private static function attestationStatementSupportManager(): AttestationStatementSupportManager
    {
        $manager = AttestationStatementSupportManager::create();
        $manager->add(PackedAttestationStatementSupport::create(Manager::create()->add(ES256::create())));

        return $manager;
    }

    private static function creationOptions(): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create(),
            PublicKeyCredentialUserEntity::create('test@foo.com', random_bytes(64), 'Test'),
            base64_decode(
                '32urRB1LDfyfYeU9myCPfrhrvNoVI27//+PWWYVxAISpIm3GqgX+jNudPgvOZy96UPNvEkCWCArW0jtpQZFGAg==',
                true
            ),
            [],
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
        );
    }

    private static function registrationFromYubicoSecurityKey(): PublicKeyCredential
    {
        $serializer = (new WebauthnSerializerFactory(self::attestationStatementSupportManager()))->create();

        return $serializer->deserialize(
            '{"id":"xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI-lqXl7ndKW-n8JFYsBCuKbZA3zRAUxAZDHG_tXHsAi6TbO0Q","type":"public-key","rawId":"xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI+lqXl7ndKW+n8JFYsBCuKbZA3zRAUxAZDHG/tXHsAi6TbO0Q==","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiIzMnVyUkIxTERmeWZZZVU5bXlDUGZyaHJ2Tm9WSTI3X18tUFdXWVZ4QUlTcEltM0dxZ1gtak51ZFBndk9aeTk2VVBOdkVrQ1dDQXJXMGp0cFFaRkdBZyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAOkogofSKvV0ma9Ejb3WH44tmXrUhSNK5qg7blgjR1n8AiEAuMsQaAsw27slMfM+wLfe4ozk+Mv8Rxdluhj59hLP4fxjeDVjgVkCwjCCAr4wggGmoAMCAQICBHSG/cIwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG8xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE5NTUwMDM4NDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASVXfOt9yR9MXXv/ZzE8xpOh4664YEJVmFQ+ziLLl9lJ79XQJqlgaUNCsUvGERcChNUihNTyKTlmnBOUjvATevto2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBD4oBHzjApNFYAGFxEfntx9MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBADFcSIDmmlJ+OGaJvWn9CqhvSeueToVFQVVvqtALOgCKHdwB+Wx29mg2GpHiMsgQp5xjB0ybbnpG6x212FxESJ+GinZD0ipchi7APwPlhIvjgH16zVX44a4e4hOsc6tLIOP71SaMsHuHgCcdH0vg5d2sc006WJe9TXO6fzV+ogjJnYpNKQLmCXoAXE3JBNwKGBIOCvfQDPyWmiiG5bGxYfPty8Z3pnjX+1MDnM2hhr40ulMxlSNDnX/ZSnDyMGIbk8TOQmjTF02UO8auP8k3wt5D1rROIRU9+FCSX5WQYi68RuDrGMZB8P5+byoJqbKQdxn2LmE1oZAyohPAmLcoPO5oYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAHz4oBHzjApNFYAGFxEfntx9AEDFjDeASPQtUvzclfPugovXhdCOH1bU0wWtMAtYj6WpeXud0pb6fwkViwEK4ptkDfNEBTEBkMcb+1cewCLpNs7RpQECAyYgASFYIBECPLnZwCFJ/2Pam0zUQOi4QQAwCKdAZ++36lPi7yvbIlgg4+9scyMxQeQjYGIgli1h5Sh2mlv8BwXwwQKUvbtS+KY="}}',
            PublicKeyCredential::class,
            'json'
        );
    }
}
