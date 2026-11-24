<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Event\AttestationCheckedAgainstMetadata;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\Service\ChainedMetadataServices;
use Webauthn\MetadataService\Service\LocalResourceMetadataService;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;

/**
 * Registrations through the validator, with metadata that know the Security Key by Yubico and neither the FIDO
 * conformance authenticator "4b46ebe2-9866-427e-b7a4-ab926b2aa12f" nor the null AAGUID of a U2F security key.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1002
 * @internal
 */
final class AttestationCheckedAgainstMetadataTest extends AbstractTestCase
{
    private const UNKNOWN_AAGUID = '4b46ebe2-9866-427e-b7a4-ab926b2aa12f';

    private const NULL_AAGUID = '00000000-0000-0000-0000-000000000000';

    #[Test]
    public function anAuthenticatorTheMetadataDoNotKnowIsRefusedByDefault(): void
    {
        $factory = $this->factory();
        $factory->enableMetadataStatementSupport(
            $this->metadataStatementRepository(),
            new StatusReportRepository(),
            PhpCertificateChainValidator::create($this->client, $this->clock),
        );
        [$response, $options] = $this->unknownAuthenticatorRegistration();

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            sprintf('The Metadata Statement for the AAGUID "%s" is missing', self::UNKNOWN_AAGUID)
        );

        AuthenticatorAttestationResponseValidator::create($factory->creationCeremony())
            ->check($response, $options, 'webauthn.spomky-labs.com');
    }

    #[Test]
    public function anAuthenticatorTheMetadataDoNotKnowIsRegisteredUnverifiedWhenNoStatementIsRequired(): void
    {
        $factory = $this->factory();
        $factory->enableMetadataStatementSupport(
            $this->metadataStatementRepository(),
            new StatusReportRepository(),
            PhpCertificateChainValidator::create($this->client, $this->clock),
            false,
        );
        $events = [];
        $factory->setEventDispatcher($this->eventDispatcher($events));
        [$response, $options] = $this->unknownAuthenticatorRegistration();

        $credentialRecord = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony())
            ->check($response, $options, 'webauthn.spomky-labs.com');

        static::assertSame(self::UNKNOWN_AAGUID, $credentialRecord->aaguid->toRfc4122());
        static::assertCount(1, $events);
        static::assertSame($credentialRecord, $events[0]->credentialRecord);
        static::assertFalse($events[0]->isVerified());
        static::assertNull($events[0]->metadataStatement);
    }

    #[Test]
    public function anAuthenticatorTheMetadataKnowIsRegisteredVerified(): void
    {
        $factory = $this->factory();
        $factory->enableMetadataStatementSupport(
            $this->metadataStatementRepository(),
            new StatusReportRepository(),
            PhpCertificateChainValidator::create($this->client, $this->clock),
        );
        $events = [];
        $factory->setEventDispatcher($this->eventDispatcher($events));
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create(),
            PublicKeyCredentialUserEntity::create('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            base64_decode(
                '32urRB1LDfyfYeU9myCPfrhrvNoVI27//+PWWYVxAISpIm3GqgX+jNudPgvOZy96UPNvEkCWCArW0jtpQZFGAg==',
                true
            ),
            [],
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
        );
        $response = $this->getSerializer()
            ->deserialize(
                '{"id":"xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI-lqXl7ndKW-n8JFYsBCuKbZA3zRAUxAZDHG_tXHsAi6TbO0Q","type":"public-key","rawId":"xYw3gEj0LVL83JXz7oKL14XQjh9W1NMFrTALWI+lqXl7ndKW+n8JFYsBCuKbZA3zRAUxAZDHG/tXHsAi6TbO0Q==","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiIzMnVyUkIxTERmeWZZZVU5bXlDUGZyaHJ2Tm9WSTI3X18tUFdXWVZ4QUlTcEltM0dxZ1gtak51ZFBndk9aeTk2VVBOdkVrQ1dDQXJXMGp0cFFaRkdBZyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAOkogofSKvV0ma9Ejb3WH44tmXrUhSNK5qg7blgjR1n8AiEAuMsQaAsw27slMfM+wLfe4ozk+Mv8Rxdluhj59hLP4fxjeDVjgVkCwjCCAr4wggGmoAMCAQICBHSG/cIwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG8xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE5NTUwMDM4NDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASVXfOt9yR9MXXv/ZzE8xpOh4664YEJVmFQ+ziLLl9lJ79XQJqlgaUNCsUvGERcChNUihNTyKTlmnBOUjvATevto2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBD4oBHzjApNFYAGFxEfntx9MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBADFcSIDmmlJ+OGaJvWn9CqhvSeueToVFQVVvqtALOgCKHdwB+Wx29mg2GpHiMsgQp5xjB0ybbnpG6x212FxESJ+GinZD0ipchi7APwPlhIvjgH16zVX44a4e4hOsc6tLIOP71SaMsHuHgCcdH0vg5d2sc006WJe9TXO6fzV+ogjJnYpNKQLmCXoAXE3JBNwKGBIOCvfQDPyWmiiG5bGxYfPty8Z3pnjX+1MDnM2hhr40ulMxlSNDnX/ZSnDyMGIbk8TOQmjTF02UO8auP8k3wt5D1rROIRU9+FCSX5WQYi68RuDrGMZB8P5+byoJqbKQdxn2LmE1oZAyohPAmLcoPO5oYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAHz4oBHzjApNFYAGFxEfntx9AEDFjDeASPQtUvzclfPugovXhdCOH1bU0wWtMAtYj6WpeXud0pb6fwkViwEK4ptkDfNEBTEBkMcb+1cewCLpNs7RpQECAyYgASFYIBECPLnZwCFJ/2Pam0zUQOi4QQAwCKdAZ++36lPi7yvbIlgg4+9scyMxQeQjYGIgli1h5Sh2mlv8BwXwwQKUvbtS+KY="}}',
                PublicKeyCredential::class,
                'json'
            )->response;
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);

        $credentialRecord = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony())
            ->check($response, $options, 'localhost');

        static::assertCount(1, $events);
        static::assertSame($credentialRecord, $events[0]->credentialRecord);
        static::assertTrue($events[0]->isVerified());
        static::assertSame('Security Key by Yubico', $events[0]->metadataStatement?->description);
    }

    #[Test]
    public function aFullAttestationUnderTheNullAaguidIsRegisteredUnverifiedWhenNoStatementIsRequired(): void
    {
        $factory = $this->factory();
        $factory->enableMetadataStatementSupport(
            $this->metadataStatementRepository(),
            new StatusReportRepository(),
            PhpCertificateChainValidator::create($this->client, $this->clock),
            false,
        );
        $events = [];
        $factory->setEventDispatcher($this->eventDispatcher($events));
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('', 'localhost'),
            PublicKeyCredentialUserEntity::create('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            random_bytes(32),
            [],
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
        );
        $response = $this->getSerializer()
            ->deserialize(SoftwareAuthenticator::fidoU2f($options->challenge), PublicKeyCredential::class, 'json')
            ->response;
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);

        $credentialRecord = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony())
            ->check($response, $options, 'localhost');

        static::assertSame(self::NULL_AAGUID, $credentialRecord->aaguid->toRfc4122());
        static::assertCount(1, $events);
        static::assertSame($credentialRecord, $events[0]->credentialRecord);
        static::assertFalse($events[0]->isVerified());
    }

    private function factory(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAttestationStatementSupportManager(new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
            new FidoU2FAttestationStatementSupport(),
            new PackedAttestationStatementSupport(Manager::create()->add(ES256::create())),
        ]));
        $factory->setAllowedOrigins(
            ['https://localhost', 'https://localhost:8443', 'https://webauthn.spomky-labs.com']
        );

        return $factory;
    }

    private function metadataStatementRepository(): MetadataStatementRepository
    {
        return new MetadataStatementRepository(ChainedMetadataServices::create(
            LocalResourceMetadataService::create(__DIR__ . '/../../metadataStatements/yubikey.json')
        ));
    }

    /**
     * @param AttestationCheckedAgainstMetadata[] $events
     */
    private function eventDispatcher(array &$events): EventDispatcher
    {
        $eventDispatcher = new EventDispatcher();
        $eventDispatcher->addListener(
            AttestationCheckedAgainstMetadata::class,
            static function (AttestationCheckedAgainstMetadata $event) use (&$events): void {
                $events[] = $event;
            }
        );

        return $eventDispatcher;
    }

    /**
     * The FIDO conformance authenticator sends a packed full attestation for an AAGUID no statement describes.
     *
     * @return array{AuthenticatorAttestationResponse, PublicKeyCredentialCreationOptions}
     */
    private function unknownAuthenticatorRegistration(): array
    {
        $options = $this->getSerializer()
            ->deserialize(
                '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"625PSan72RKYZz_TA4aOLx7ohRptcGnJme6z4k4k6tU","attestation":"direct","user":{"name":"um-3Ch1opGUBzAgO0VE5","id":"OTk3OGFlYWItNmE5Yi00ZDNlLTk2ODMtOWM3MDViNWNiYjAw","displayName":"Christiana Muntz"},"authenticatorSelection":{"userVerification":"preferred"},"timeout":60000}',
                PublicKeyCredentialCreationOptions::class,
                'json'
            );
        $response = $this->getSerializer()
            ->deserialize(
                '{"id":"8cQglUiAnc63hmOyudycW7xdaJoH-pPVlRyg5Xl7aYM","rawId":"8cQglUiAnc63hmOyudycW7xdaJoH+pPVlRyg5Xl7aYM","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhALCSEVyBYqnkYZmp-ZGpnS3qgaYzEu-cOafnRqyFyvgVAiEAxjsiNt3SdvBc7Lwq9O2CSLRF6OQDDB0D1lBHNYiFV4FjeDVjgVkERTCCBEEwggIpoAMCAQICAQEwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA1MjMxNDM5NDNaFw0yODA1MjAxNDM5NDNaMIHCMSMwIQYDVQQDDBpGSURPMiBCQVRDSCBLRVkgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQsFAAOCAgEAh92gn_ggiQXRLUHOCaTp1HpcBhsOw8ZwTKJBxwYK8ycQ5_QRXBcMRi8axVexH2HoUDTg_u-DkvH2UYGYjX_RAxgGIh4dPgrKXwVndtMwiI5QnQwXMocKtzyyeuSQv6INwk_QCuJL5LOAyPtNUWMTb_UvCcdYWjtZYFOeYQSK9T_6dtWSp6XAhIT4wf3CBaxyai-YiRn3nfi154vUrqtuDh56eODK7-Iezg9npbucln3XxW_kRhtk2FERSBmBoo7IotPd8NGTATnwUvt16vw6x3mW2a6zZGOOeYCQmeXlfNza7fSff1BdFWR5f4cJ0gFAv297Tf5dGZQvZD3DcyQ9OJeJ3RQQ9inX0Nhxk1-6cm1i2e8h9gTN7otjqYmnGjs3ezhPdax2AdrmckO43YNuchfTPECPTRzP4rQo3QbwGLeEAk_HV-oJmYiBkdhf2F2QLMm7SdeqZ1Jjg1W1vNJT288vj1EGF-_aKXg_bujAaK86_YNPBJaW9Rdw4EnfFUi5bEdkD5ZSpeAHCQzCDn2RzkBjs2rTFe4qRFUWtC-RZ4wFqRx70jXLIw-ArpeetpjtzJSNqQsqPlEvpyMxuV2ZjnruA2_ysP3RDzqNs7R8JVNKiie0RAbG7et43ULZcC7oix8JKYsJ6wDmX8Gyy7vWM-LS9XiZUH37sEvwKJbM-xxoYXV0aERhdGFYpJYE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZQQAAAFpLRuvimGZCfrekq5JrKqEvACDxxCCVSICdzreGY7K53JxbvF1omgf6k9WVHKDleXtpg6UBAgMmIAEhWCCPnYovnhb8uFlbWx3AJ68r1nA-r3Rp77jZ7QrzCi6LfyJYIIIvljxQ2lTzNH1o8YxxCLkUXT7NZP9Jf4pKHSLTkhka","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IjYyNVBTYW43MlJLWVp6X1RBNGFPTHg3b2hScHRjR25KbWU2ejRrNGs2dFUiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}',
                PublicKeyCredential::class,
                'json'
            )->response;
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);

        return [$response, $options];
    }
}
