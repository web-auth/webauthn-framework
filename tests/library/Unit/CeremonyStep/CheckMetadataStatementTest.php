<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\CeremonyStep;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\CeremonyStep\CheckMetadataStatement;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Event\AttestationCheckedAgainstMetadata;
use Webauthn\Event\CompromisedAuthenticatorDetected;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\CertificateChainException;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\Statement\StatusReport;
use Webauthn\MetadataService\StatusReportRepository;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * A full attestation (basic, AttCA, AnonCA) whose AAGUID has no Metadata Statement is refused, unless the metadata
 * support does not require a statement: it then passes unverified. The outcome and the status reports reach the
 * application through events, and a listener may admit a compromised authenticator.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1002
 * @internal
 */
final class CheckMetadataStatementTest extends TestCase
{
    private const KNOWN_AAGUID = 'f8a011f3-8c0a-4d15-8006-17111f9edc7d';

    private const UNKNOWN_AAGUID = '4b46ebe2-9866-427e-b7a4-ab926b2aa12f';

    private const NULL_AAGUID = '00000000-0000-0000-0000-000000000000';

    private const LEAF_CERTIFICATE = 'leaf-certificate';

    private const PINNED_TRUST_ANCHOR = 'pinned-trust-anchor';

    /**
     * @return iterable<string, array{string}>
     */
    public static function aaguidsTheMetadataDoNotKnow(): iterable
    {
        yield 'an AAGUID without statement' => [self::UNKNOWN_AAGUID];
        yield 'the null AAGUID' => [self::NULL_AAGUID];
    }

    #[Test]
    #[DataProvider('aaguidsTheMetadataDoNotKnow')]
    public function anUnknownAuthenticatorIsRefusedByDefault(string $aaguid): void
    {
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([]),
            static::createStub(CertificateChainValidator::class),
        );

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(sprintf('The Metadata Statement for the AAGUID "%s" is missing', $aaguid));

        $this->process($step, AttestationStatement::TYPE_BASIC, $aaguid);
    }

    #[Test]
    #[DataProvider('aaguidsTheMetadataDoNotKnow')]
    public function anUnknownAuthenticatorPassesUnverifiedWhenNoStatementIsRequired(string $aaguid): void
    {
        $certificateChainValidator = $this->createMock(CertificateChainValidator::class);
        $certificateChainValidator->expects(static::never())
            ->method('check');
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([]),
            $certificateChainValidator,
            false,
        );
        $events = $this->recordEvents($step);
        $credentialRecord = $this->credentialRecord($aaguid);

        $this->process($step, AttestationStatement::TYPE_BASIC, $aaguid, $credentialRecord);

        static::assertCount(1, $events->checked);
        static::assertSame($credentialRecord, $events->checked[0]->credentialRecord);
        static::assertNull($events->checked[0]->metadataStatement);
        static::assertSame([], $events->checked[0]->statusReports);
        static::assertFalse($events->checked[0]->isVerified());
    }

    #[Test]
    public function aKnownAuthenticatorIsStillVerifiedWhenNoStatementIsRequired(): void
    {
        $statementRepository = $this->statementRepository();
        $metadataStatement = $statementRepository->findOneByAAGUID(self::KNOWN_AAGUID);
        static::assertNotNull($metadataStatement);
        $certificateChainValidator = $this->createMock(CertificateChainValidator::class);
        $certificateChainValidator->expects(static::once())
            ->method('check')
            ->with(
                [self::LEAF_CERTIFICATE],
                CertificateToolbox::fixPEMStructures($metadataStatement->attestationRootCertificates)
            );
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $statementRepository,
            $this->statusReportRepository([]),
            $certificateChainValidator,
            false,
        );
        $events = $this->recordEvents($step);

        $this->process($step, AttestationStatement::TYPE_BASIC, self::KNOWN_AAGUID);

        static::assertCount(1, $events->checked);
        static::assertSame($metadataStatement, $events->checked[0]->metadataStatement);
        static::assertTrue($events->checked[0]->isVerified());
    }

    #[Test]
    public function theStatusReportsReachTheApplication(): void
    {
        $knownStatusReports = [
            $this->statusReport(AuthenticatorStatus::FIDO_CERTIFIED),
            $this->statusReport(AuthenticatorStatus::FIDO_CERTIFIED_L1),
        ];
        $unknownStatusReports = [$this->statusReport(AuthenticatorStatus::NOT_FIDO_CERTIFIED)];
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::KNOWN_AAGUID => $knownStatusReports,
                self::UNKNOWN_AAGUID => $unknownStatusReports,
            ]),
            static::createStub(CertificateChainValidator::class),
            false,
        );
        $events = $this->recordEvents($step);

        $this->process($step, AttestationStatement::TYPE_BASIC, self::KNOWN_AAGUID);
        $this->process($step, AttestationStatement::TYPE_BASIC, self::UNKNOWN_AAGUID);

        static::assertCount(2, $events->checked);
        static::assertSame($knownStatusReports, $events->checked[0]->statusReports);
        static::assertTrue($events->checked[0]->isVerified());
        static::assertSame($unknownStatusReports, $events->checked[1]->statusReports);
        static::assertFalse($events->checked[1]->isVerified());
    }

    #[Test]
    public function aKnownAuthenticatorWithAnUntrustedChainIsStillRefusedWhenNoStatementIsRequired(): void
    {
        $certificateChainValidator = static::createStub(CertificateChainValidator::class);
        $certificateChainValidator->method('check')
            ->willThrowException(CertificateChainException::create([], [], 'Unable to validate the certificate chain.'));
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([]),
            $certificateChainValidator,
            false,
        );
        $events = $this->recordEvents($step);

        try {
            $this->process($step, AttestationStatement::TYPE_BASIC, self::KNOWN_AAGUID);
            static::fail('The attestation should have been refused.');
        } catch (CertificateChainException $exception) {
            static::assertSame('Unable to validate the certificate chain.', $exception->getMessage());
        }
        static::assertSame([], $events->checked);
    }

    #[Test]
    public function theAttestationTypeOfAKnownAuthenticatorIsStillCheckedWhenNoStatementIsRequired(): void
    {
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([]),
            static::createStub(CertificateChainValidator::class),
            false,
        );

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            'Invalid attestation statement. The attestation type "attca" is not allowed for this authenticator.'
        );

        $this->process($step, AttestationStatement::TYPE_ATTCA, self::KNOWN_AAGUID);
    }

    #[Test]
    public function aSelfAttestationOfAnUnknownAuthenticatorKeepsItsHandlingWhenNoStatementIsRequired(): void
    {
        $certificateChainValidator = $this->createMock(CertificateChainValidator::class);
        $certificateChainValidator->expects(static::never())
            ->method('check');
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::UNKNOWN_AAGUID => [$this->statusReport(AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE)],
            ]),
            $certificateChainValidator,
            false,
        );
        $events = $this->recordEvents($step);

        $this->process($step, AttestationStatement::TYPE_SELF, self::UNKNOWN_AAGUID);

        static::assertSame([], $events->compromised);
        static::assertSame([], $events->checked);
    }

    #[Test]
    public function aSelfAttestationUnderTheNullAaguidKeepsItsHandlingWhenNoStatementIsRequired(): void
    {
        $statementRepository = $this->createMock(MetadataStatementRepository::class);
        $statementRepository->expects(static::never())
            ->method('findOneByAAGUID');
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $statementRepository,
            $this->statusReportRepository([]),
            static::createStub(CertificateChainValidator::class),
            false,
        );
        $events = $this->recordEvents($step);

        $this->process($step, AttestationStatement::TYPE_SELF, self::NULL_AAGUID);

        static::assertSame([], $events->checked);
    }

    #[Test]
    public function nothingIsDispatchedWhenTheOptionsDoNotAskForAnAttestation(): void
    {
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::KNOWN_AAGUID => [$this->statusReport(AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE)],
            ]),
            static::createStub(CertificateChainValidator::class),
            false,
        );
        $events = $this->recordEvents($step);

        $this->process(
            $step,
            AttestationStatement::TYPE_BASIC,
            self::KNOWN_AAGUID,
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE
        );

        static::assertSame([], $events->compromised);
        static::assertSame([], $events->checked);
    }

    #[Test]
    public function nothingIsDispatchedForAnEnterpriseAttestationVerifiedUpToThePinnedTrustAnchors(): void
    {
        $certificateChainValidator = $this->createMock(CertificateChainValidator::class);
        $certificateChainValidator->expects(static::once())
            ->method('check')
            ->with([self::LEAF_CERTIFICATE], CertificateToolbox::fixPEMStructures([self::PINNED_TRUST_ANCHOR]));
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([]),
            $certificateChainValidator,
            false,
        );
        $step->setEnterpriseAttestationTrustAnchors([self::PINNED_TRUST_ANCHOR]);
        $events = $this->recordEvents($step);

        $this->process(
            $step,
            AttestationStatement::TYPE_BASIC,
            self::UNKNOWN_AAGUID,
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE
        );

        static::assertSame([], $events->checked);
    }

    #[Test]
    public function theRepositoryIsStillMandatoryWithoutMetadataSupport(): void
    {
        $step = new CheckMetadataStatement();
        $step->enableCertificateChainValidator(static::createStub(CertificateChainValidator::class));

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            'The Metadata Statement Repository is mandatory when requesting attestation objects.'
        );

        $this->process($step, AttestationStatement::TYPE_BASIC, self::UNKNOWN_AAGUID);
    }

    #[Test]
    public function aCompromisedAuthenticatorIsRefusedByDefault(): void
    {
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::KNOWN_AAGUID => [$this->statusReport(AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE)],
            ]),
            static::createStub(CertificateChainValidator::class),
        );

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('The authenticator is compromised and cannot be used');

        $this->process($step, AttestationStatement::TYPE_BASIC, self::KNOWN_AAGUID);
    }

    #[Test]
    public function aCompromisedAuthenticatorIsRefusedWhenNoListenerAdmitsIt(): void
    {
        $statusReports = [
            $this->statusReport(AuthenticatorStatus::USER_VERIFICATION_BYPASS),
            $this->statusReport(AuthenticatorStatus::FIDO_CERTIFIED),
        ];
        $statementRepository = $this->statementRepository();
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $statementRepository,
            $this->statusReportRepository([
                self::KNOWN_AAGUID => $statusReports,
            ]),
            static::createStub(CertificateChainValidator::class),
        );
        $events = $this->recordEvents($step);
        $credentialRecord = $this->credentialRecord(self::KNOWN_AAGUID);

        try {
            $this->process($step, AttestationStatement::TYPE_BASIC, self::KNOWN_AAGUID, $credentialRecord);
            static::fail('The compromised authenticator should have been refused.');
        } catch (AuthenticatorResponseVerificationException $exception) {
            static::assertSame('The authenticator is compromised and cannot be used', $exception->getMessage());
        }
        static::assertCount(1, $events->compromised);
        static::assertSame($credentialRecord, $events->compromised[0]->credentialRecord);
        static::assertSame($statusReports, $events->compromised[0]->statusReports);
        static::assertSame([$statusReports[0]], $events->compromised[0]->compromisedStatusReports());
        static::assertSame(
            $statementRepository->findOneByAAGUID(self::KNOWN_AAGUID),
            $events->compromised[0]->metadataStatement
        );
        static::assertFalse($events->compromised[0]->isAdmitted());
        static::assertSame([], $events->checked);
    }

    #[Test]
    public function theApplicationDecidesOnceForEveryReportThatFlagsTheAuthenticator(): void
    {
        $statusReports = [
            $this->statusReport(AuthenticatorStatus::REVOKED),
            $this->statusReport(AuthenticatorStatus::UPDATE_AVAILABLE),
            $this->statusReport(AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE),
            $this->statusReport(AuthenticatorStatus::FIDO_CERTIFIED),
        ];
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::KNOWN_AAGUID => $statusReports,
            ]),
            static::createStub(CertificateChainValidator::class),
        );
        $events = $this->recordEvents($step, true);

        $this->process($step, AttestationStatement::TYPE_BASIC, self::KNOWN_AAGUID);

        static::assertCount(1, $events->compromised);
        static::assertSame(
            [$statusReports[0], $statusReports[2]],
            $events->compromised[0]->compromisedStatusReports()
        );
        static::assertCount(1, $events->checked);
        static::assertSame($statusReports, $events->checked[0]->statusReports);
    }

    #[Test]
    public function aListenerCanAdmitACompromisedAuthenticator(): void
    {
        $statusReports = [$this->statusReport(AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE)];
        $certificateChainValidator = $this->createMock(CertificateChainValidator::class);
        $certificateChainValidator->expects(static::once())
            ->method('check');
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::KNOWN_AAGUID => $statusReports,
            ]),
            $certificateChainValidator,
        );
        $events = $this->recordEvents($step, true);

        $this->process($step, AttestationStatement::TYPE_BASIC, self::KNOWN_AAGUID);

        static::assertCount(1, $events->compromised);
        static::assertTrue($events->compromised[0]->isAdmitted());
        static::assertCount(1, $events->checked);
        static::assertTrue($events->checked[0]->isVerified());
        static::assertSame($statusReports, $events->checked[0]->statusReports);
    }

    #[Test]
    public function anUnknownAuthenticatorReportedAsCompromisedIsRefusedWhenNoStatementIsRequired(): void
    {
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::UNKNOWN_AAGUID => [$this->statusReport(AuthenticatorStatus::USER_KEY_REMOTE_COMPROMISE)],
            ]),
            static::createStub(CertificateChainValidator::class),
            false,
        );
        $events = $this->recordEvents($step);

        try {
            $this->process($step, AttestationStatement::TYPE_BASIC, self::UNKNOWN_AAGUID);
            static::fail('The compromised authenticator should have been refused.');
        } catch (AuthenticatorResponseVerificationException $exception) {
            static::assertSame('The authenticator is compromised and cannot be used', $exception->getMessage());
        }
        static::assertCount(1, $events->compromised);
        static::assertNull($events->compromised[0]->metadataStatement);
        static::assertSame([], $events->checked);
    }

    #[Test]
    public function aListenerCanAdmitAnUnknownAuthenticatorReportedAsCompromisedWhenNoStatementIsRequired(): void
    {
        $statusReports = [$this->statusReport(AuthenticatorStatus::USER_KEY_REMOTE_COMPROMISE)];
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::UNKNOWN_AAGUID => $statusReports,
            ]),
            static::createStub(CertificateChainValidator::class),
            false,
        );
        $events = $this->recordEvents($step, true);

        $this->process($step, AttestationStatement::TYPE_BASIC, self::UNKNOWN_AAGUID);

        static::assertCount(1, $events->compromised);
        static::assertCount(1, $events->checked);
        static::assertFalse($events->checked[0]->isVerified());
        static::assertSame($statusReports, $events->checked[0]->statusReports);
    }

    #[Test]
    public function aListenerCanAdmitACompromisedAuthenticatorThatUsesSelfAttestation(): void
    {
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::KNOWN_AAGUID => [$this->statusReport(AuthenticatorStatus::USER_KEY_PHYSICAL_COMPROMISE)],
            ]),
            static::createStub(CertificateChainValidator::class),
        );
        $events = $this->recordEvents($step, true);

        $this->process($step, AttestationStatement::TYPE_SELF, self::KNOWN_AAGUID);

        static::assertCount(1, $events->compromised);
        static::assertTrue($events->compromised[0]->isAdmitted());
        static::assertSame([], $events->checked);
    }

    #[Test]
    public function aCompromisedAuthenticatorVerifiedUpToThePinnedTrustAnchorsIsRefusedWhenNoListenerAdmitsIt(): void
    {
        $certificateChainValidator = $this->createMock(CertificateChainValidator::class);
        $certificateChainValidator->expects(static::never())
            ->method('check');
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::KNOWN_AAGUID => [$this->statusReport(AuthenticatorStatus::REVOKED)],
            ]),
            $certificateChainValidator,
        );
        $step->setEnterpriseAttestationTrustAnchors([self::PINNED_TRUST_ANCHOR]);
        $events = $this->recordEvents($step);

        try {
            $this->process(
                $step,
                AttestationStatement::TYPE_BASIC,
                self::KNOWN_AAGUID,
                null,
                PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE
            );
            static::fail('The compromised authenticator should have been refused.');
        } catch (AuthenticatorResponseVerificationException $exception) {
            static::assertSame('The authenticator is compromised and cannot be used', $exception->getMessage());
        }
        static::assertCount(1, $events->compromised);
        static::assertNull($events->compromised[0]->metadataStatement);
    }

    #[Test]
    public function aListenerCanAdmitACompromisedAuthenticatorVerifiedUpToThePinnedTrustAnchors(): void
    {
        $certificateChainValidator = $this->createMock(CertificateChainValidator::class);
        $certificateChainValidator->expects(static::once())
            ->method('check')
            ->with([self::LEAF_CERTIFICATE], CertificateToolbox::fixPEMStructures([self::PINNED_TRUST_ANCHOR]));
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport(
            $this->statementRepository(),
            $this->statusReportRepository([
                self::KNOWN_AAGUID => [$this->statusReport(AuthenticatorStatus::REVOKED)],
            ]),
            $certificateChainValidator,
        );
        $step->setEnterpriseAttestationTrustAnchors([self::PINNED_TRUST_ANCHOR]);
        $events = $this->recordEvents($step, true);

        $this->process(
            $step,
            AttestationStatement::TYPE_BASIC,
            self::KNOWN_AAGUID,
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE
        );

        static::assertCount(1, $events->compromised);
        static::assertTrue($events->compromised[0]->isAdmitted());
        static::assertSame([], $events->checked);
    }

    private function process(
        CheckMetadataStatement $step,
        string $attestationType,
        string $aaguid,
        ?CredentialRecord $credentialRecord = null,
        string $attestation = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
    ): void {
        $trustPath = $attestationType === AttestationStatement::TYPE_SELF
            ? EmptyTrustPath::create()
            : CertificateTrustPath::create([self::LEAF_CERTIFICATE]);
        $authenticatorData = AuthenticatorData::create(
            '',
            str_repeat("\0", 32),
            "\x41",
            0,
            AttestedCredentialData::create(Uuid::fromString($aaguid), 'credential-id'),
        );
        $response = AuthenticatorAttestationResponse::create(
            CollectedClientData::create('{}', [
                'type' => 'webauthn.create',
                'challenge' => 'challenge-bytes',
                'origin' => 'https://example.com',
            ]),
            AttestationObject::create(
                '',
                AttestationStatement::create('packed', [], $attestationType, $trustPath),
                $authenticatorData
            ),
        );
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('', 'example.com'),
            PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice'),
            'challenge-bytes',
            [],
            null,
            $attestation,
        );

        $step->process(
            $credentialRecord ?? $this->credentialRecord($aaguid),
            $response,
            $options,
            'user-handle',
            'example.com'
        );
    }

    private function credentialRecord(string $aaguid): CredentialRecord
    {
        return CredentialRecord::create(
            'credential-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_BASIC,
            EmptyTrustPath::create(),
            Uuid::fromString($aaguid),
            'public-key',
            'user-handle',
            0,
        );
    }

    /**
     * The repository knows one authenticator model: the Security Key by Yubico.
     */
    private function statementRepository(): MetadataStatementRepository
    {
        $content = file_get_contents(__DIR__ . '/../../../metadataStatements/yubikey.json');
        static::assertIsString($content);
        $metadataStatement = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))
            ->create()
            ->deserialize($content, MetadataStatement::class, 'json');

        return new class($metadataStatement) implements MetadataStatementRepository {
            public function __construct(
                private readonly MetadataStatement $metadataStatement
            ) {
            }

            public function findOneByAAGUID(string $aaguid): ?MetadataStatement
            {
                return $aaguid === $this->metadataStatement->aaguid ? $this->metadataStatement : null;
            }
        };
    }

    /**
     * @param array<string, StatusReport[]> $statusReports
     */
    private function statusReportRepository(array $statusReports): StatusReportRepository
    {
        return new class($statusReports) implements StatusReportRepository {
            /**
             * @param array<string, StatusReport[]> $statusReports
             */
            public function __construct(
                private readonly array $statusReports
            ) {
            }

            public function findStatusReportsByAAGUID(string $aaguid): array
            {
                return $this->statusReports[$aaguid] ?? [];
            }
        };
    }

    private function statusReport(string $status): StatusReport
    {
        return StatusReport::create($status, '2026-11-01', null, null, null, null, null, null);
    }

    /**
     * @return object{checked: AttestationCheckedAgainstMetadata[], compromised: CompromisedAuthenticatorDetected[]}
     */
    private function recordEvents(CheckMetadataStatement $step, bool $admit = false): object
    {
        $events = new class() {
            /**
             * @var AttestationCheckedAgainstMetadata[]
             */
            public array $checked = [];

            /**
             * @var CompromisedAuthenticatorDetected[]
             */
            public array $compromised = [];
        };
        $eventDispatcher = new EventDispatcher();
        $eventDispatcher->addListener(
            AttestationCheckedAgainstMetadata::class,
            static function (AttestationCheckedAgainstMetadata $event) use ($events): void {
                $events->checked[] = $event;
            }
        );
        $eventDispatcher->addListener(
            CompromisedAuthenticatorDetected::class,
            static function (CompromisedAuthenticatorDetected $event) use ($events, $admit): void {
                if ($admit) {
                    $event->admit();
                }
                $events->compromised[] = $event;
            }
        );
        $step->setEventDispatcher($eventDispatcher);

        return $events;
    }
}
