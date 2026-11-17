<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\CertificateChainException;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;
use Webauthn\MetadataService\Statement\StatusReport;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\InMemoryMetadata;
use Webauthn\Tests\PackedAttestationFixture;

/**
 * Issue #1003: an enterprise attestation chains to a root CA of the organization, which no metadata statement lists.
 * The relying party pins its trust anchors on the creation ceremony. Under the "enterprise" conveyance preference, a
 * full attestation is then verified up to these anchors only, and the status reports of its AAGUID still apply.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1003
 * @internal
 */
final class EnterpriseAttestationTest extends TestCase
{
    private const CHALLENGE = 'challenge-of-the-registration-ceremony';

    /**
     * @return iterable<string, array{string}>
     */
    public static function creationCeremonies(): iterable
    {
        yield 'creation' => ['creation'];
        yield 'conditional creation' => ['conditional creation'];
    }

    #[Test]
    #[DataProvider('creationCeremonies')]
    public function anEnterpriseAttestationChainingToAPinnedTrustAnchorIsAccepted(string $ceremony): void
    {
        $factory = $this->factory();
        $factory->setEnterpriseAttestationTrustAnchors([
            PackedAttestationFixture::rootCertificate(PackedAttestationFixture::ORGANIZATION),
        ]);

        $credentialRecord = $this->validator($factory, $ceremony)
            ->check(
                $this->response(PackedAttestationFixture::ORGANIZATION, PackedAttestationFixture::MANAGED_DEVICE_AAGUID),
                $this->creationOptions(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE),
                'localhost'
            );

        static::assertSame(AttestationStatement::TYPE_BASIC, $credentialRecord->attestationType);
        static::assertSame(PackedAttestationFixture::MANAGED_DEVICE_AAGUID, $credentialRecord->aaguid->toRfc4122());
    }

    #[Test]
    public function withoutPinnedTrustAnchorsAnEnterpriseAttestationNeedsAMetadataStatement(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            'The Metadata Statement for the AAGUID "dd4ec289-e01d-41c9-bb89-70fa845d4bf2" is missing'
        );

        $this->validator($this->factory())
            ->check(
                $this->response(PackedAttestationFixture::ORGANIZATION, PackedAttestationFixture::MANAGED_DEVICE_AAGUID),
                $this->creationOptions(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE),
                'localhost'
            );
    }

    #[Test]
    public function theRootsOfAMetadataStatementDoNotCountBesideThePinnedTrustAnchors(): void
    {
        $organizationRoot = PackedAttestationFixture::rootCertificate(PackedAttestationFixture::ORGANIZATION);
        $factory = $this->factory();
        $factory->setEnterpriseAttestationTrustAnchors([$organizationRoot]);

        try {
            $this->validator($factory)
                ->check(
                    $this->response(PackedAttestationFixture::VENDOR, PackedAttestationFixture::VENDOR_AAGUID),
                    $this->creationOptions(
                        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE
                    ),
                    'localhost'
                );
            static::fail('A full attestation chaining to none of the pinned trust anchors must be refused.');
        } catch (CertificateChainException $exception) {
            static::assertSame([trim($organizationRoot)], $exception->trustedCertificates);
        }
    }

    #[Test]
    public function thePinnedTrustAnchorsDoNotChangeTheOtherConveyancePreferences(): void
    {
        $factory = $this->factory();
        $factory->setEnterpriseAttestationTrustAnchors([
            PackedAttestationFixture::rootCertificate(PackedAttestationFixture::ORGANIZATION),
        ]);
        $validator = $this->validator($factory);

        $credentialRecord = $validator->check(
            $this->response(PackedAttestationFixture::VENDOR, PackedAttestationFixture::VENDOR_AAGUID),
            $this->creationOptions(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT),
            'localhost'
        );
        static::assertSame(PackedAttestationFixture::VENDOR_AAGUID, $credentialRecord->aaguid->toRfc4122());

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            'The Metadata Statement for the AAGUID "dd4ec289-e01d-41c9-bb89-70fa845d4bf2" is missing'
        );
        $validator->check(
            $this->response(PackedAttestationFixture::ORGANIZATION, PackedAttestationFixture::MANAGED_DEVICE_AAGUID),
            $this->creationOptions(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT),
            'localhost'
        );
    }

    #[Test]
    public function theStatusReportsOfTheAaguidStillApply(): void
    {
        $factory = $this->factory([
            PackedAttestationFixture::MANAGED_DEVICE_AAGUID => [
                InMemoryMetadata::statusReport(AuthenticatorStatus::USER_KEY_REMOTE_COMPROMISE),
            ],
        ]);
        $factory->setEnterpriseAttestationTrustAnchors([
            PackedAttestationFixture::rootCertificate(PackedAttestationFixture::ORGANIZATION),
        ]);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('The authenticator is compromised and cannot be used');

        $this->validator($factory)
            ->check(
                $this->response(PackedAttestationFixture::ORGANIZATION, PackedAttestationFixture::MANAGED_DEVICE_AAGUID),
                $this->creationOptions(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE),
                'localhost'
            );
    }

    /**
     * @param array<string, StatusReport[]> $statusReports
     */
    private function factory(array $statusReports = []): CeremonyStepManagerFactory
    {
        $metadata = new InMemoryMetadata([
            PackedAttestationFixture::VENDOR_AAGUID => InMemoryMetadata::statement(
                PackedAttestationFixture::VENDOR_AAGUID,
                [
                    base64_encode(
                        PackedAttestationFixture::der(
                            PackedAttestationFixture::rootCertificate(PackedAttestationFixture::VENDOR)
                        )
                    ),
                ]
            ),
        ], $statusReports);
        $factory = new CeremonyStepManagerFactory();
        $factory->setAttestationStatementSupportManager(PackedAttestationFixture::attestationStatementSupportManager());
        $factory->setAllowedOrigins(['https://localhost']);
        $factory->enableMetadataStatementSupport(
            $metadata,
            $metadata,
            PhpCertificateChainValidator::create(new MockHttpClient(), new MockClock('2027-06-01'))
        );

        return $factory;
    }

    private function validator(
        CeremonyStepManagerFactory $factory,
        string $ceremony = 'creation'
    ): AuthenticatorAttestationResponseValidator {
        return AuthenticatorAttestationResponseValidator::create(
            $ceremony === 'creation' ? $factory->creationCeremony() : $factory->conditionalCreateCeremony()
        );
    }

    private function response(string $issuer, string $aaguid): AuthenticatorAttestationResponse
    {
        $response = PackedAttestationFixture::credential($issuer, $aaguid, self::CHALLENGE)->response;
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);

        return $response;
    }

    private function creationOptions(string $attestation): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('Example', 'localhost'),
            PublicKeyCredentialUserEntity::create('alice', 'alice-handle', 'Alice'),
            self::CHALLENGE,
            [PublicKeyCredentialParameters::createPk(-7)],
            attestation: $attestation,
        );
    }
}
