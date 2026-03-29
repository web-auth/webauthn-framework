<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Webauthn\CeremonyStep\CheckAllowedOrigins;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\Tests\AbstractTestCase;

final class CheckAllowedOriginsTest extends AbstractTestCase
{
    #[Test]
    public function originIsNotInAllowedOrigins(): void
    {
        // Then
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid origin');

        // Given
        $checkOrigins = new CheckAllowedOrigins(['https://example.org']);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'example.org',
        );
    }

    #[Test]
    public function originIsValid(): void
    {
        // Given
        $checkOrigins = new CheckAllowedOrigins(['https://webauthn.spomky-labs.com']);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'webauthn.spomky-labs.com',
        );

        // Then
        static::assertTrue(true);
    }

    #[Test]
    public function validSubdomainWithAllowSubdomains(): void
    {
        // Given
        $checkOrigins = new CheckAllowedOrigins(['spomky-labs.com'], true);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'spomky-labs.com',
        );

        // Then
        static::assertTrue(true);
    }

    #[Test]
    public function invalidSubdomainWithoutAllowSubdomains(): void
    {
        // Then
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid origin');

        // Given
        $checkOrigins = new CheckAllowedOrigins(['https://spomky-labs.com']);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'spomky-labs.com',
        );
    }

    #[Test]
    public function emptyAllowedOriginsDefaultsToHttps(): void
    {
        // Given
        $checkOrigins = new CheckAllowedOrigins([]);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'webauthn.spomky-labs.com',
        );

        // Then
        static::assertTrue(true); // if no exception, test passes
    }

    #[Test]
    public function emptyAllowedOriginsWithoutSubdomains(): void
    {
        // Then
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid origin. Subdomains are not allowed.');

        // Given
        $checkOrigins = new CheckAllowedOrigins([], false);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'spomky-labs.com',
        );
    }

    #[Test]
    public function emptyAllowedOriginsWithSubdomains(): void
    {
        // Given
        $checkOrigins = new CheckAllowedOrigins([], true);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'spomky-labs.com',
        );

        // Then
        static::assertTrue(true); // if no exception, test passes
    }

    #[Test]
    public function emptyAllowedOriginsWithoutSubdomainsAndValidHost(): void
    {
        // Given
        $checkOrigins = new CheckAllowedOrigins([], false);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'webauthn.spomky-labs.com',
        );

        // Then
        static::assertTrue(true); // if no exception, test passes
    }

    #[Test]
    public function differentPortIsRejected(): void
    {
        // PoC from GHSA-f7pm-6hr8-7ggm: different port on same host must be rejected
        // C.origin = https://webauthn.spomky-labs.com (port 443)
        // Allowed = https://webauthn.spomky-labs.com:8443 (port 8443)
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid origin');

        $checkOrigins = new CheckAllowedOrigins(['https://webauthn.spomky-labs.com:8443']);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'webauthn.spomky-labs.com',
        );
    }

    #[Test]
    public function explicitDefaultPortMatchesImplicitPort(): void
    {
        // https://webauthn.spomky-labs.com:443 should match https://webauthn.spomky-labs.com
        $checkOrigins = new CheckAllowedOrigins(['https://webauthn.spomky-labs.com:443']);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'webauthn.spomky-labs.com',
        );

        static::assertTrue(true);
    }

    #[Test]
    public function httpSchemeIsRejectedWhenHttpsIsConfigured(): void
    {
        // Allowed = https://webauthn.spomky-labs.com
        // C.origin = https://webauthn.spomky-labs.com (matches, but testing that http:// would not)
        // We test by configuring http:// and verifying it rejects https:// origin
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid origin');

        $checkOrigins = new CheckAllowedOrigins(['http://webauthn.spomky-labs.com']);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'webauthn.spomky-labs.com',
        );
    }

    #[Test]
    public function emptyAllowedOriginsWithSubdomainsAndInvalidHost(): void
    {
        // Then
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid origin. Subdomains are not allowed.');

        // Given
        $checkOrigins = new CheckAllowedOrigins([], false);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->getPublicKeyCredential();

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'spomky-labs.com',
        );
    }

    #[Test]
    public function differentPortShouldBeRejected(): void
    {
        // Then
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid origin');

        // Given
        $checkOrigins = new CheckAllowedOrigins(['https://login.example.com:8443']);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->createPublicKeyCredentialWithOrigin('https://login.example.com');

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'login.example.com',
        );
    }

    #[Test]
    public function differentSchemeShouldBeRejected(): void
    {
        // Then
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid origin');

        // Given
        $checkOrigins = new CheckAllowedOrigins(['http://login.example.com']);
        $publicKeyCredentialSource = $this->getPublicKeyCredentialSource();
        $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions();
        $publicKeyCredential = $this->createPublicKeyCredentialWithOrigin('https://login.example.com');

        // When
        $checkOrigins->process(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            null,
            'login.example.com',
        );
    }

    private function createPublicKeyCredentialWithOrigin(string $origin): PublicKeyCredential
    {
        $clientDataJson = json_encode([
            'origin' => $origin,
            'challenge' => '8hPZ5agbQx6bCw_X9c75JyE3DP1PAvW1wv3WknpqBhc',
            'type' => 'webauthn.create',
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $clientDataJsonB64 = rtrim(strtr(base64_encode($clientDataJson), '+/', '-_'), '=');

        $json = '{"id":"12Q1ykFsRWcUbO_y23o3cimk9Bn3rFahaKEAUHyMjrg","rawId":"12Q1ykFsRWcUbO_y23o3cimk9Bn3rFahaKEAUHyMjrg","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAIVT1JJcjJlU4xyiEWB1DO3OqMLJdC62t8es-JvwbDTgAiEA4E9bIHL-bq4_r09qUBDcm-qCqz0a7NP42K_fSj1YoqBjeDVjglkCkjCCAo4wggI0oAMCAQICAQEwCgYIKoZIzj0EAwIwga8xJjAkBgNVBAMMHUZJRE8yIElOVEVSTUVESUFURSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDUyMzE0Mzc0MVoXDTI4MDUyMDE0Mzc0MVowgcIxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLrZYqzxrVIvmvsKDJIcF9vrOpmT0KSjZmO-xPXL8hr7gGRpZRxRkYP0fJEPzCo0ZTK3D-vHFtsdDgG9V24pSGSjLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFEpU5QbSkURPbQ8zXdb9x0ZsuV9UMAoGCCqGSM49BAMCA0gAMEUCIQC5Wza0c32jrBDTDb7165XlBCdCWkSVfzvhhqHTfyfqRQIgTQuswDhApHwqT_X6W8aYccqenKb9HKF8DNaRhHM3KXhZBDUwggQxMIICGaADAgECAgECMA0GCSqGSIb3DQEBCwUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNzIzMTQyOTA3WhcNNDUxMjA4MTQyOTA3WjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATcQR3fVW1_TXOMqXUUelVx9GMAKSPWb7R7XpeHIHBZBQ7JzoepbzRXitTdCLTCfNXpLE1G6JRcstPmX9tLSXnzoy8wLTAMBgNVHRMEBTADAQH_MB0GA1UdDgQWBBRnwRmSkFv1XQDB1iEOjC12IZJHwDANBgkqhkiG9w0BAQsFAAOCAgEAC5gup7NUuwcndifv5dwlZ6GISPTEciQdMxmNo9nE9BRAO2btQ0DdJdifA8GnQQd29dIgk8U48WucY4qzuvRZaK6z6AIrU2bAUlJrKnlTZvjdiM3oiTY9WTiB9eyfmK_ZgEv7W9DEFW7vrh32-pjSNF1VyxuMEpna1X6syqtNDVG-w0YLjdkXi0ciuRJy0Q9A90vmMKgAxgnRfCol5aQUlHpZMTiK-8OCp8sSoq05QN39iy34u4AeKGUWeuKjYEwNsgKgn-v1-A1dbUw2cWYg53Oi5m_DQLlt-Ws1hokuwXxCekaBvieB9nu13fYXv7SkgwuWPNwyFPlQkWpIPgb9eZME3knUiJ2EAS1UE7kraWNg3cQO2v6tY24-5-FmEyuWinGChrHswT0sYtmhQGlWa0bCV9fELL69bCO64RiWoenLsiX15hmmC7-ZbF9D1VHj1BHR9eioAZUVonEiDJSZHtVxXlmU3jQBhrEPztF5Rn670dzq_E4HLPfzbrKW-L2F2i-WEWF7cticNVBBLXUHsFAvGYMqv7DE0zDGaZ7L-jXIjSCiE2IjixChMYw_aFYwmx0N6yuXeJDYu8fCSXOKTPR6ZRsLCQ38tXFSQRyn1T5Fgvxds7Q2sxgtVXCNy8FMoof27gjMu5i4pAt2ldXEOx1zI2P-Nv6GFxY2U_BtXINoYXV0aERhdGFYpJYE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZQQAAABuA9T0ehS5D7bs_0C8TIuWvACDXZDXKQWxFZxRs7_LbejdyKaT0GfesVqFooQBQfIyOuKUBAgMmIAEhWCCR3V4iMssbPhNCS1rk4wtdZKaqX9L5e3DwGUJKi0OBgCJYIKBBtvFMQHD3m-EgmcQOXmQhctxiyh68RT1QmNq_xWm4","clientDataJSON":"' . $clientDataJsonB64 . '"},"getClientExtensionResults":{},"type":"public-key"}';

        return $this->getSerializer()
            ->deserialize($json, PublicKeyCredential::class, 'json');
    }

    private function getPublicKeyCredentialSource(): PublicKeyCredentialSource
    {
        return $this->createPublicKeyCredentialSource(
            base64_decode(
                'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                true
            ),
            'foo',
            100,
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            base64_decode(
                'pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=',
                true
            )
        );
    }

    private function getPublicKeyCredential(): PublicKeyCredential
    {
        return $this->getSerializer()
            ->deserialize(
                '{"id":"12Q1ykFsRWcUbO_y23o3cimk9Bn3rFahaKEAUHyMjrg","rawId":"12Q1ykFsRWcUbO_y23o3cimk9Bn3rFahaKEAUHyMjrg","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAIVT1JJcjJlU4xyiEWB1DO3OqMLJdC62t8es-JvwbDTgAiEA4E9bIHL-bq4_r09qUBDcm-qCqz0a7NP42K_fSj1YoqBjeDVjglkCkjCCAo4wggI0oAMCAQICAQEwCgYIKoZIzj0EAwIwga8xJjAkBgNVBAMMHUZJRE8yIElOVEVSTUVESUFURSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDUyMzE0Mzc0MVoXDTI4MDUyMDE0Mzc0MVowgcIxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLrZYqzxrVIvmvsKDJIcF9vrOpmT0KSjZmO-xPXL8hr7gGRpZRxRkYP0fJEPzCo0ZTK3D-vHFtsdDgG9V24pSGSjLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFEpU5QbSkURPbQ8zXdb9x0ZsuV9UMAoGCCqGSM49BAMCA0gAMEUCIQC5Wza0c32jrBDTDb7165XlBCdCWkSVfzvhhqHTfyfqRQIgTQuswDhApHwqT_X6W8aYccqenKb9HKF8DNaRhHM3KXhZBDUwggQxMIICGaADAgECAgECMA0GCSqGSIb3DQEBCwUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNzIzMTQyOTA3WhcNNDUxMjA4MTQyOTA3WjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATcQR3fVW1_TXOMqXUUelVx9GMAKSPWb7R7XpeHIHBZBQ7JzoepbzRXitTdCLTCfNXpLE1G6JRcstPmX9tLSXnzoy8wLTAMBgNVHRMEBTADAQH_MB0GA1UdDgQWBBRnwRmSkFv1XQDB1iEOjC12IZJHwDANBgkqhkiG9w0BAQsFAAOCAgEAC5gup7NUuwcndifv5dwlZ6GISPTEciQdMxmNo9nE9BRAO2btQ0DdJdifA8GnQQd29dIgk8U48WucY4qzuvRZaK6z6AIrU2bAUlJrKnlTZvjdiM3oiTY9WTiB9eyfmK_ZgEv7W9DEFW7vrh32-pjSNF1VyxuMEpna1X6syqtNDVG-w0YLjdkXi0ciuRJy0Q9A90vmMKgAxgnRfCol5aQUlHpZMTiK-8OCp8sSoq05QN39iy34u4AeKGUWeuKjYEwNsgKgn-v1-A1dbUw2cWYg53Oi5m_DQLlt-Ws1hokuwXxCekaBvieB9nu13fYXv7SkgwuWPNwyFPlQkWpIPgb9eZME3knUiJ2EAS1UE7kraWNg3cQO2v6tY24-5-FmEyuWinGChrHswT0sYtmhQGlWa0bCV9fELL69bCO64RiWoenLsiX15hmmC7-ZbF9D1VHj1BHR9eioAZUVonEiDJSZHtVxXlmU3jQBhrEPztF5Rn670dzq_E4HLPfzbrKW-L2F2i-WEWF7cticNVBBLXUHsFAvGYMqv7DE0zDGaZ7L-jXIjSCiE2IjixChMYw_aFYwmx0N6yuXeJDYu8fCSXOKTPR6ZRsLCQ38tXFSQRyn1T5Fgvxds7Q2sxgtVXCNy8FMoof27gjMu5i4pAt2ldXEOx1zI2P-Nv6GFxY2U_BtXINoYXV0aERhdGFYpJYE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZQQAAABuA9T0ehS5D7bs_0C8TIuWvACDXZDXKQWxFZxRs7_LbejdyKaT0GfesVqFooQBQfIyOuKUBAgMmIAEhWCCR3V4iMssbPhNCS1rk4wtdZKaqX9L5e3DwGUJKi0OBgCJYIKBBtvFMQHD3m-EgmcQOXmQhctxiyh68RT1QmNq_xWm4","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IjhoUFo1YWdiUXg2YkN3X1g5Yzc1SnlFM0RQMVBBdlcxd3YzV2tucHFCaGMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"getClientExtensionResults":{},"type":"public-key"}',
                PublicKeyCredential::class,
                'json'
            );
    }

    private function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->getSerializer()
            ->deserialize(
                '{"rp":{"name":"Webauthn Demo, by Spomky-Labs","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-46},{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39},{"type":"public-key","alg":-65535}],"challenge":"8hPZ5agbQx6bCw_X9c75JyE3DP1PAvW1wv3WknpqBhc","attestation":"direct","user":{"name":"DQ3SnF1Eeq5Av2WCPtlP","id":"MDFHN1JTR1RKTk5OVEpFOUUyS1M2Q0I1U1M","displayName":"Clarice Zemlicka"},"authenticatorSelection":{"userVerification":"preferred"},"excludeCredentials":[],"timeout":60000,"status":"ok","errorMessage":""}',
                PublicKeyCredentialRequestOptions::class,
                'json'
            );
    }
}
