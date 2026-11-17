<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpClient\MockHttpClient;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\CertificateChainException;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\Service\LocalResourceMetadataService;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;

/**
 * The AAGUID is written by the authenticator. Under the null AAGUID, a full attestation still has to chain to the
 * trust anchors of a Metadata Statement: tests/metadataStatements/null-aaguid.json gives the suite the Apple WebAuthn
 * Root CA and the Yubico U2F root for it, so the self-made certificates of SoftwareAuthenticator reach none of them.
 *
 * @internal
 */
final class NullAaguidAttestationTest extends AbstractTestCase
{
    private const NULL_AAGUID = '00000000-0000-0000-0000-000000000000';

    private const SECURITY_KEY_BY_YUBICO = 'f8a011f3-8c0a-4d15-8006-17111f9edc7d';

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function selfMadeFullAttestations(): iterable
    {
        yield 'packed under the AAGUID of a known model' => ['packed', self::SECURITY_KEY_BY_YUBICO];
        yield 'packed under the null AAGUID' => ['packed', self::NULL_AAGUID];
        yield 'fido-u2f' => ['fido-u2f', self::NULL_AAGUID];
        yield 'apple under the null AAGUID' => ['apple', self::NULL_AAGUID];
    }

    #[Test]
    #[DataProvider('selfMadeFullAttestations')]
    public function aFullAttestationThatReachesNoTrustAnchorIsRefusedWhateverItsAaguid(
        string $format,
        string $aaguid
    ): void {
        $options = self::creationOptions();
        $response = $this->getSerializer()
            ->deserialize(self::register($format, $options->challenge, $aaguid), PublicKeyCredential::class, 'json')
            ->response;
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);

        $this->expectException(CertificateChainException::class);
        $this->expectExceptionMessage('Unable to validate the certificate chain.');

        $this->getAuthenticatorAttestationResponseValidator()
            ->check($response, $options, 'localhost');
    }

    #[Test]
    public function aFullAttestationUnderTheNullAaguidIsRefusedWithoutAMetadataStatementForIt(): void
    {
        $attestationStatementSupportManager = AttestationStatementSupportManager::create(
            [FidoU2FAttestationStatementSupport::create()]
        );
        $ceremonyStepManagerFactory = new CeremonyStepManagerFactory();
        $ceremonyStepManagerFactory->setAttestationStatementSupportManager($attestationStatementSupportManager);
        $ceremonyStepManagerFactory->enableMetadataStatementSupport(
            new MetadataStatementRepository(
                LocalResourceMetadataService::create(__DIR__ . '/../../metadataStatements/yubikey.json')
            ),
            new StatusReportRepository(),
            PhpCertificateChainValidator::create(new MockHttpClient())
        );
        $options = self::creationOptions();
        $response = (new WebauthnSerializerFactory($attestationStatementSupportManager))
            ->create()
            ->deserialize(SoftwareAuthenticator::fidoU2f($options->challenge), PublicKeyCredential::class, 'json')
            ->response;
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            'The Metadata Statement for the AAGUID "00000000-0000-0000-0000-000000000000" is missing'
        );

        AuthenticatorAttestationResponseValidator::create($ceremonyStepManagerFactory->creationCeremony())
            ->check($response, $options, 'localhost');
    }

    private static function creationOptions(): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('', 'localhost'),
            PublicKeyCredentialUserEntity::create('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            random_bytes(32),
            [],
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
        );
    }

    private static function register(string $format, string $challenge, string $aaguid): string
    {
        return match ($format) {
            'packed' => SoftwareAuthenticator::packed($challenge, $aaguid),
            'fido-u2f' => SoftwareAuthenticator::fidoU2f($challenge),
            'apple' => SoftwareAuthenticator::apple($challenge, $aaguid),
        };
    }
}
