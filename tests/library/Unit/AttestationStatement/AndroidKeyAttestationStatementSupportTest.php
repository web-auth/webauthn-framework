<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Exception\AttestationStatementLoadingException;
use Webauthn\Exception\AttestationStatementVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class AndroidKeyAttestationStatementSupportTest extends AbstractTestCase
{
    private const VALID_ATTESTATION = '{"rawId":"AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c","id":"AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c","response": {"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVGY2NWJTNkQ1dGVtaDJCd3ZwdHFnQlBiMjVpWkRSeGp3QzVhbnM5MUlJSkRyY3JPcG5XVEs0TFZnRmplVVY0R0RNZTQ0dzhTSTVOc1pzc0lYVFV2RGciLCJvcmlnaW4iOiJodHRwczpcL1wvd2ViYXV0aG4ub3JnIiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiY29tLmFuZHJvaWQuY2hyb21lIn0","attestationObject":"o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiAsp6jPtimcSgc-fgIsVwgqRsZX6eU7KKbkVGWa0CRJlgIgH5yuf_laPyNy4PlS6e8ZHjs57iztxGiTqO7G91sdlWBjeDVjg1kCzjCCAsowggJwoAMCAQICAQEwCgYIKoZIzj0EAwIwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxOzA5BgNVBAMMMkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlMB4XDTE4MTIwMjA5MTAyNVoXDTI4MTIwMjA5MTAyNVowHzEdMBsGA1UEAwwUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ4SaIP3ibDSwCIORpYJ3g9_5OICxZUCIqt-vV6JZVJoXQ8S1JFzyaFz5EFQ2fNT6-5SE5wWTZRAR_A3M52IcaPo4IBMTCCAS0wCwYDVR0PBAQDAgeAMIH8BgorBgEEAdZ5AgERBIHtMIHqAgECCgEAAgEBCgEBBCAqQ4LXu9idi1vfF3LP7MoUOSSHuf1XHy63K9-X3gbUtgQAMIGCv4MQCAIGAWduLuFwv4MRCAIGAbDqja1wv4MSCAIGAbDqja1wv4U9CAIGAWduLt_ov4VFTgRMMEoxJDAiBB1jb20uZ29vZ2xlLmF0dGVzdGF0aW9uZXhhbXBsZQIBATEiBCBa0F7CIcj4OiJhJ97FV1AMPldLxgElqdwhywvkoAZglTAzoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBF7-DeQMCAR6_hT4DAgEAMB8GA1UdIwQYMBaAFD_8rNYasTqegSC41SUcxWW7HpGpMAoGCCqGSM49BAMCA0gAMEUCIGd3OQiTgFX9Y07kE-qvwh2Kx6lEG9-Xr2ORT5s7AK_-AiEAucDIlFjCUo4rJfqIxNY93HXhvID7lNzGIolS0E-BJBhZAnwwggJ4MIICHqADAgECAgIQATAKBggqhkjOPQQDAjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MB4XDTE2MDExMTAwNDYwOVoXDTI2MDEwODAwNDYwOVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxOzA5BgNVBAMMMkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6555-EJjWazLKpFMiYbMcK2QZpOCqXMmE_6sy_ghJ0whdJdKKv6luU1_ZtTgZRBmNbxTt6CjpnFYPts-Ea4QFKNmMGQwHQYDVR0OBBYEFD_8rNYasTqegSC41SUcxWW7HpGpMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMBIGA1UdEwEB_wQIMAYBAf8CAQAwDgYDVR0PAQH_BAQDAgKEMAoGCCqGSM49BAMCA0gAMEUCIEuKm3vugrzAM4euL8CJmLTdw42rJypFn2kMx8OS1A-OAiEA7toBXbb0MunUhDtiTJQE7zp8zL1e-yK75_65dz9ZP_tZAo8wggKLMIICMqADAgECAgkAogWe0Q5DW1cwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQzNTBaFw0zNjAxMDYwMDQzNTBaMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATuXV7H4cDbbQOmfua2G-xNal1qaC4P_39JDn13H0Qibb2xr_oWy8etxXfSVpyqt7AtVAFdPkMrKo7XTuxIdUGko2MwYTAdBgNVHQ4EFgQUyK3pd0xFw6PPDRYQ5HlDOiFaMM8wHwYDVR0jBBgwFoAUyK3pd0xFw6PPDRYQ5HlDOiFaMM8wDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAoQwCgYIKoZIzj0EAwIDRwAwRAIgNSGj74s0Rh6c1WDzHViJIGrco2VB9g2ezooZjGZIYHsCIE0L81HZMHx9W9o1NB2oRxtjpYVlPK1PJKfnTa9BffG_aGF1dGhEYXRhWMWVaQiPHs7jIylUA129ENfK45EwWidRtVm7j9fLsim91EUAAAAAKPN9K5K4QcSwKoYM73zANABBAVUvAmX241vMKYd7ZBdmkNWaYcNYhoSZCJjFRGmROb6I4ygQUVmH6k9IMwcbZGeAQ4v4WMNphORudwje5h7ty9ClAQIDJiABIVggOEmiD94mw0sAiDkaWCd4Pf-TiAsWVAiKrfr1eiWVSaEiWCB0PEtSRc8mhc-RBUNnzU-vuUhOcFk2UQEfwNzOdiHGjw"},"type":"public-key"}';

    /**
     * Explicit tag 702 (origin) holding the INTEGER 0 (KM_ORIGIN_GENERATED).
     */
    private const DER_ORIGIN_GENERATED = 'bf853e03020100';

    /**
     * Explicit tag 1 (purpose) holding a SET containing the INTEGER 2 (KM_PURPOSE_SIGN).
     */
    private const DER_PURPOSE_SIGN = 'a1053103020102';

    #[Test]
    public function loadingAttestationWithoutSignatureThrowsException(): void
    {
        // Then
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('The attestation statement value "sig" is missing.');

        // Given
        $support = AndroidKeyAttestationStatementSupport::create();

        static::assertSame('android-key', $support->name());

        // When
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [],
        ]));
    }

    #[Test]
    public function loadingAttestationWithoutCertificateListThrowsException(): void
    {
        // Then
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('The attestation statement value "x5c" is missing.');

        // Given
        $support = AndroidKeyAttestationStatementSupport::create();

        // When
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [
                'sig' => 'foo-bar',
            ],
        ]));
    }

    #[Test]
    public function loadingAttestationWithoutAlgorithmParameterThrowsException(): void
    {
        // Then
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('The attestation statement value "alg" is missing.');

        // Given
        $support = AndroidKeyAttestationStatementSupport::create();

        // When
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [
                'sig' => 'foo-bar',
                'x5c' => [],
            ],
        ]));
    }

    #[Test]
    public function loadingAttestationWithEmptyCertificateListThrowsException(): void
    {
        // Then
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage(
            'The attestation statement value "x5c" must be a list with at least one certificate.'
        );

        // Given
        $support = AndroidKeyAttestationStatementSupport::create();

        static::assertSame('android-key', $support->name());

        // When
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [
                'sig' => 'foo-bar',
                'x5c' => [],
                'alg' => -7,
            ],
        ]));
    }

    #[Test]
    public function validatingAttestationStatementWithValidInputSucceeds(): void
    {
        // Given
        $support = AndroidKeyAttestationStatementSupport::create();
        $manager = AttestationStatementSupportManager::create();
        $manager->add($support);
        $input = self::VALID_ATTESTATION;
        $publicKeyCredential = $this->getSerializer()
            ->deserialize($input, PublicKeyCredential::class, 'json');
        /** @var AuthenticatorAttestationResponse $response */
        $response = $publicKeyCredential->response;
        $clientDataJSONHash = hash('sha256', $response->clientDataJSON->rawData, true);

        // When
        $result = $support->isValid(
            $clientDataJSONHash,
            $response->attestationObject
                ->attStmt,
            $response->attestationObject
                ->authData
        );

        // Then
        static::assertTrue($result);
    }

    #[Test]
    public function anImportedKeyIsRejected(): void
    {
        // Then
        $this->expectException(AttestationStatementVerificationException::class);
        $this->expectExceptionMessage('The key was not generated by the authenticator');

        // Given
        $input = $this->patchAttestation(self::DER_ORIGIN_GENERATED, 'bf853e03020102');

        // When
        $this->validate($input);
    }

    #[Test]
    public function aKeyThatIsNotAllowedToSignIsRejected(): void
    {
        // Then
        $this->expectException(AttestationStatementVerificationException::class);
        $this->expectExceptionMessage('The key is not allowed to sign');

        // Given
        $input = $this->patchAttestation(self::DER_PURPOSE_SIGN, 'a1053103020103');

        // When
        $this->validate($input);
    }

    #[Test]
    public function anAttestationWithoutOriginIsRejected(): void
    {
        // Then
        $this->expectException(AttestationStatementVerificationException::class);
        $this->expectExceptionMessage('The origin field is missing from the authorization lists');

        // Given
        $input = $this->patchAttestation(self::DER_ORIGIN_GENERATED, 'bf853d03020100');

        // When
        $this->validate($input);
    }

    #[Test]
    public function anAttestationWithoutPurposeIsRejected(): void
    {
        // Then
        $this->expectException(AttestationStatementVerificationException::class);
        $this->expectExceptionMessage('The purpose field is missing from the authorization lists');

        // Given
        $input = $this->patchAttestation(self::DER_PURPOSE_SIGN, 'a9053103020102');

        // When
        $this->validate($input);
    }

    /**
     * Both replacements keep the DER length untouched, so only the patched value differs from the valid attestation.
     * The attestation signature covers the authenticator data and the client data hash, not the certificate, and the
     * certificate chain is not verified here, so the patched attestation only exercises the authorization lists.
     */
    private function patchAttestation(string $search, string $replacement): string
    {
        $data = json_decode(self::VALID_ATTESTATION, true, 512, JSON_THROW_ON_ERROR);
        $attestationObject = Base64UrlSafe::decodeNoPadding($data['response']['attestationObject']);
        $patched = str_replace(hex2bin($search), hex2bin($replacement), $attestationObject, $count);
        static::assertSame(1, $count);
        $data['response']['attestationObject'] = Base64UrlSafe::encodeUnpadded($patched);

        return json_encode($data, JSON_THROW_ON_ERROR);
    }

    private function validate(string $input): void
    {
        $support = AndroidKeyAttestationStatementSupport::create();
        $publicKeyCredential = $this->getSerializer()
            ->deserialize($input, PublicKeyCredential::class, 'json');
        /** @var AuthenticatorAttestationResponse $response */
        $response = $publicKeyCredential->response;
        $clientDataJSONHash = hash('sha256', $response->clientDataJSON->rawData, true);

        $support->isValid(
            $clientDataJSONHash,
            $response->attestationObject
                ->attStmt,
            $response->attestationObject
                ->authData
        );
    }
}
