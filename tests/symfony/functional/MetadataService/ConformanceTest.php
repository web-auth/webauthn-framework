<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\MetadataService;

use InvalidArgumentException;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpClient\Response\MockResponse;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\Tests\Bundle\Functional\MockClientCallback;
use Webauthn\Tests\MockedRequestTrait;
use Webauthn\TrustPath\CertificateTrustPath;

/**
 * @internal
 */
final class ConformanceTest extends KernelTestCase
{
    use MockedRequestTrait;

    /**
     * @test
     */
    public function theMetadataStatementIsMissing(): never
    {
        $callback = self::getContainer()->get(MockClientCallback::class);
        $callback->addResponses([
            'GET-https://fidoalliance.co.nz/blob.jwt' => new MockResponse(trim(
                file_get_contents(__DIR__ . '/../../../blob.jwt')
            )),
        ]);
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The Metadata Statement for the AAGUID "4b46ebe2-9866-427e-b7a4-ab926b2aa12f" is missing'
        );

        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"625PSan72RKYZz_TA4aOLx7ohRptcGnJme6z4k4k6tU","attestation":"direct","user":{"name":"um-3Ch1opGUBzAgO0VE5","id":"OTk3OGFlYWItNmE5Yi00ZDNlLTk2ODMtOWM3MDViNWNiYjAw","displayName":"Christiana Muntz"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        $result = '{"id":"8cQglUiAnc63hmOyudycW7xdaJoH-pPVlRyg5Xl7aYM","rawId":"8cQglUiAnc63hmOyudycW7xdaJoH+pPVlRyg5Xl7aYM","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhALCSEVyBYqnkYZmp-ZGpnS3qgaYzEu-cOafnRqyFyvgVAiEAxjsiNt3SdvBc7Lwq9O2CSLRF6OQDDB0D1lBHNYiFV4FjeDVjgVkERTCCBEEwggIpoAMCAQICAQEwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA1MjMxNDM5NDNaFw0yODA1MjAxNDM5NDNaMIHCMSMwIQYDVQQDDBpGSURPMiBCQVRDSCBLRVkgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQsFAAOCAgEAh92gn_ggiQXRLUHOCaTp1HpcBhsOw8ZwTKJBxwYK8ycQ5_QRXBcMRi8axVexH2HoUDTg_u-DkvH2UYGYjX_RAxgGIh4dPgrKXwVndtMwiI5QnQwXMocKtzyyeuSQv6INwk_QCuJL5LOAyPtNUWMTb_UvCcdYWjtZYFOeYQSK9T_6dtWSp6XAhIT4wf3CBaxyai-YiRn3nfi154vUrqtuDh56eODK7-Iezg9npbucln3XxW_kRhtk2FERSBmBoo7IotPd8NGTATnwUvt16vw6x3mW2a6zZGOOeYCQmeXlfNza7fSff1BdFWR5f4cJ0gFAv297Tf5dGZQvZD3DcyQ9OJeJ3RQQ9inX0Nhxk1-6cm1i2e8h9gTN7otjqYmnGjs3ezhPdax2AdrmckO43YNuchfTPECPTRzP4rQo3QbwGLeEAk_HV-oJmYiBkdhf2F2QLMm7SdeqZ1Jjg1W1vNJT288vj1EGF-_aKXg_bujAaK86_YNPBJaW9Rdw4EnfFUi5bEdkD5ZSpeAHCQzCDn2RzkBjs2rTFe4qRFUWtC-RZ4wFqRx70jXLIw-ArpeetpjtzJSNqQsqPlEvpyMxuV2ZjnruA2_ysP3RDzqNs7R8JVNKiie0RAbG7et43ULZcC7oix8JKYsJ6wDmX8Gyy7vWM-LS9XiZUH37sEvwKJbM-xxoYXV0aERhdGFYpJYE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZQQAAAFpLRuvimGZCfrekq5JrKqEvACDxxCCVSICdzreGY7K53JxbvF1omgf6k9WVHKDleXtpg6UBAgMmIAEhWCCPnYovnhb8uFlbWx3AJ68r1nA-r3Rp77jZ7QrzCi6LfyJYIIIvljxQ2lTzNH1o8YxxCLkUXT7NZP9Jf4pKHSLTkhka","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IjYyNVBTYW43MlJLWVp6X1RBNGFPTHg3b2hScHRjR25KbWU2ejRrNGs2dFUiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load($result);
        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        $request = $this->createRequestWithHost('webauthn.spomky-labs.com');
        $response = $publicKeyCredential->getResponse();

        static::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->getType());
        static::assertSame(
            hex2bin('f1c4209548809dceb78663b2b9dc9c5bbc5d689a07fa93d5951ca0e5797b6983'),
            $descriptor->getId()
        );
        static::assertSame([], $descriptor->getTransports());

        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        static::assertSame(
            AttestationStatement::TYPE_BASIC,
            $response->getAttestationObject()
                ->getAttStmt()
                ->getType()
        );
        static::assertInstanceOf(
            CertificateTrustPath::class,
            $response->getAttestationObject()
                ->getAttStmt()
                ->getTrustPath()
        );

        self::$kernel->getContainer()->get(AuthenticatorAttestationResponseValidator::class)->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request
        );
    }
}
