<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\CeremonyStep;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\CeremonyStep\CheckMetadataStatement;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\CertificateChainException;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\InMemoryMetadata;
use Webauthn\Tests\PackedAttestationFixture;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Issue #1003: under the "enterprise" conveyance preference, a full attestation (basic, AttCA, AnonCA) is verified up
 * to the trust anchors the relying party pins, and to these only. The status reports of its AAGUID still apply. Self
 * and none attestations, the other conveyance preferences and a step without pinned trust anchors are unchanged.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1003
 * @internal
 */
final class CheckMetadataStatementTest extends TestCase
{
    private const NULL_AAGUID = '00000000-0000-0000-0000-000000000000';

    /**
     * @return iterable<string, array{string}>
     */
    public static function fullAttestationTypes(): iterable
    {
        yield 'basic' => [AttestationStatement::TYPE_BASIC];
        yield 'AttCA' => [AttestationStatement::TYPE_ATTCA];
        yield 'AnonCA' => [AttestationStatement::TYPE_ANONCA];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherConveyancePreferences(): iterable
    {
        yield 'direct' => [PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT];
        yield 'indirect' => [PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT];
    }

    #[Test]
    #[DataProvider('fullAttestationTypes')]
    public function aFullAttestationChainingToAPinnedTrustAnchorIsAccepted(string $type): void
    {
        $step = new CheckMetadataStatement();
        $step->enableCertificateChainValidator($this->certificateChainValidator());
        $step->setEnterpriseAttestationTrustAnchors([$this->organizationRoot()]);

        $this->process($step, $this->response($type, PackedAttestationFixture::ORGANIZATION));

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function aTrustAnchorCanBePinnedAsABase64EncodedDerCertificate(): void
    {
        $step = new CheckMetadataStatement();
        $step->enableCertificateChainValidator($this->certificateChainValidator());
        $step->setEnterpriseAttestationTrustAnchors([
            base64_encode(PackedAttestationFixture::der($this->organizationRoot())),
        ]);

        $this->process($step, $this->response(AttestationStatement::TYPE_BASIC, PackedAttestationFixture::ORGANIZATION));

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    #[DataProvider('fullAttestationTypes')]
    public function aFullAttestationChainingToNoneOfThePinnedTrustAnchorsIsRefused(string $type): void
    {
        $step = $this->stepWithMetadata(
            new InMemoryMetadata([
                PackedAttestationFixture::VENDOR_AAGUID => $this->vendorStatement(),
            ])
        );
        $step->setEnterpriseAttestationTrustAnchors([$this->organizationRoot()]);

        try {
            $this->process(
                $step,
                $this->response($type, PackedAttestationFixture::VENDOR, PackedAttestationFixture::VENDOR_AAGUID)
            );
            static::fail('A full attestation chaining to none of the pinned trust anchors must be refused.');
        } catch (CertificateChainException $exception) {
            static::assertSame([trim($this->organizationRoot())], $exception->trustedCertificates);
        }
    }

    #[Test]
    public function theAttestationTypesOfAMetadataStatementDoNotApplyToAPinnedEnterpriseAttestation(): void
    {
        $step = $this->stepWithMetadata(
            new InMemoryMetadata([
                PackedAttestationFixture::MANAGED_DEVICE_AAGUID => InMemoryMetadata::statement(
                    PackedAttestationFixture::MANAGED_DEVICE_AAGUID,
                    [],
                    [MetadataStatement::ATTESTATION_BASIC_SURROGATE]
                ),
            ])
        );
        $step->setEnterpriseAttestationTrustAnchors([$this->organizationRoot()]);

        $this->process($step, $this->response(AttestationStatement::TYPE_BASIC, PackedAttestationFixture::ORGANIZATION));

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function aCompromisedAuthenticatorIsRefused(): void
    {
        $step = $this->stepWithMetadata(
            new InMemoryMetadata(statusReports: [
                PackedAttestationFixture::MANAGED_DEVICE_AAGUID => [
                    InMemoryMetadata::statusReport(AuthenticatorStatus::FIDO_CERTIFIED),
                    InMemoryMetadata::statusReport(AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE),
                ],
            ])
        );
        $step->setEnterpriseAttestationTrustAnchors([$this->organizationRoot()]);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('The authenticator is compromised and cannot be used');

        $this->process($step, $this->response(AttestationStatement::TYPE_BASIC, PackedAttestationFixture::ORGANIZATION));
    }

    #[Test]
    public function aCertificateChainValidatorIsRequired(): void
    {
        $step = new CheckMetadataStatement();
        $step->setEnterpriseAttestationTrustAnchors([$this->organizationRoot()]);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            'The Certificate Chain Validator is mandatory when trust anchors are pinned for enterprise attestations.'
        );

        $this->process($step, $this->response(AttestationStatement::TYPE_BASIC, PackedAttestationFixture::ORGANIZATION));
    }

    #[Test]
    public function aFullAttestationWithoutCertificateIsRefused(): void
    {
        $step = new CheckMetadataStatement();
        $step->enableCertificateChainValidator($this->certificateChainValidator());
        $step->setEnterpriseAttestationTrustAnchors([$this->organizationRoot()]);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Certificate trust path is required for attestation verification');

        $this->process($step, $this->response(AttestationStatement::TYPE_BASIC));
    }

    #[Test]
    public function aFullAttestationWithTheNullAaguidIsVerifiedUpToThePinnedTrustAnchors(): void
    {
        $step = new CheckMetadataStatement();
        $step->enableCertificateChainValidator($this->certificateChainValidator());
        $step->setEnterpriseAttestationTrustAnchors([$this->organizationRoot()]);
        $this->process(
            $step,
            $this->response(AttestationStatement::TYPE_BASIC, PackedAttestationFixture::ORGANIZATION, self::NULL_AAGUID)
        );

        $this->expectException(CertificateChainException::class);

        $this->process(
            $step,
            $this->response(AttestationStatement::TYPE_BASIC, PackedAttestationFixture::VENDOR, self::NULL_AAGUID)
        );
    }

    #[Test]
    public function aSelfOrNoneAttestationIsNotVerifiedAgainstThePinnedTrustAnchors(): void
    {
        $step = new CheckMetadataStatement();
        $step->enableCertificateChainValidator($this->certificateChainValidator());
        $step->setEnterpriseAttestationTrustAnchors([$this->organizationRoot()]);

        $this->process($step, $this->response(AttestationStatement::TYPE_SELF));
        $this->process($step, $this->response(AttestationStatement::TYPE_NONE));

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    #[DataProvider('otherConveyancePreferences')]
    public function thePinnedTrustAnchorsDoNotApplyToTheOtherConveyancePreferences(string $attestation): void
    {
        $step = $this->stepWithMetadata(
            new InMemoryMetadata([
                PackedAttestationFixture::VENDOR_AAGUID => $this->vendorStatement(),
            ])
        );
        $step->setEnterpriseAttestationTrustAnchors([$this->organizationRoot()]);
        $this->process(
            $step,
            $this->response(
                AttestationStatement::TYPE_BASIC,
                PackedAttestationFixture::VENDOR,
                PackedAttestationFixture::VENDOR_AAGUID
            ),
            $attestation
        );

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            'The Metadata Statement for the AAGUID "dd4ec289-e01d-41c9-bb89-70fa845d4bf2" is missing'
        );

        $this->process(
            $step,
            $this->response(AttestationStatement::TYPE_BASIC, PackedAttestationFixture::ORGANIZATION),
            $attestation
        );
    }

    #[Test]
    public function withoutPinnedTrustAnchorsAnEnterpriseAttestationIsVerifiedAgainstTheMetadata(): void
    {
        $step = $this->stepWithMetadata(
            new InMemoryMetadata([
                PackedAttestationFixture::VENDOR_AAGUID => $this->vendorStatement(),
            ])
        );
        $this->process(
            $step,
            $this->response(
                AttestationStatement::TYPE_BASIC,
                PackedAttestationFixture::VENDOR,
                PackedAttestationFixture::VENDOR_AAGUID
            )
        );

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            'The Metadata Statement for the AAGUID "dd4ec289-e01d-41c9-bb89-70fa845d4bf2" is missing'
        );

        $this->process($step, $this->response(AttestationStatement::TYPE_BASIC, PackedAttestationFixture::ORGANIZATION));
    }

    private function stepWithMetadata(InMemoryMetadata $metadata): CheckMetadataStatement
    {
        $step = new CheckMetadataStatement();
        $step->enableMetadataStatementSupport($metadata, $metadata, $this->certificateChainValidator());

        return $step;
    }

    private function certificateChainValidator(): PhpCertificateChainValidator
    {
        return PhpCertificateChainValidator::create(new MockHttpClient(), new MockClock('2027-06-01'));
    }

    private function organizationRoot(): string
    {
        return PackedAttestationFixture::rootCertificate(PackedAttestationFixture::ORGANIZATION);
    }

    private function vendorStatement(): MetadataStatement
    {
        return InMemoryMetadata::statement(PackedAttestationFixture::VENDOR_AAGUID, [
            base64_encode(
                PackedAttestationFixture::der(PackedAttestationFixture::rootCertificate(PackedAttestationFixture::VENDOR))
            ),
        ]);
    }

    private function process(
        CheckMetadataStatement $step,
        AuthenticatorAttestationResponse $response,
        string $attestation = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE
    ): void {
        $step->process(
            CredentialRecord::create(
                'credential-id',
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                [],
                'packed',
                EmptyTrustPath::create(),
                Uuid::v4(),
                'public-key',
                'user-handle',
                0,
            ),
            $response,
            PublicKeyCredentialCreationOptions::create(
                PublicKeyCredentialRpEntity::create('Example', 'example.com'),
                PublicKeyCredentialUserEntity::create('alice', 'alice-handle', 'Alice'),
                'challenge-bytes',
                attestation: $attestation,
            ),
            null,
            'example.com'
        );
    }

    private function response(
        string $type,
        ?string $issuer = null,
        string $aaguid = PackedAttestationFixture::MANAGED_DEVICE_AAGUID
    ): AuthenticatorAttestationResponse {
        $trustPath = $issuer === null
            ? EmptyTrustPath::create()
            : CertificateTrustPath::create([PackedAttestationFixture::attestationCertificate($issuer)]);

        return AuthenticatorAttestationResponse::create(
            CollectedClientData::create('{}', [
                'type' => 'webauthn.create',
                'challenge' => 'challenge-bytes',
                'origin' => 'https://example.com',
            ]),
            AttestationObject::create(
                rawAttestationObject: '',
                attStmt: AttestationStatement::create('packed', [], $type, $trustPath),
                authData: AuthenticatorData::create(
                    authData: '',
                    rpIdHash: str_repeat("\0", 32),
                    flags: "\x41",
                    signCount: 0,
                    attestedCredentialData: AttestedCredentialData::create(Uuid::fromString($aaguid), 'credential-id'),
                ),
            ),
        );
    }
}
