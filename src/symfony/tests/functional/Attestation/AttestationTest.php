<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional\Attestation;

use Assert\InvalidArgumentException;
use Cose\Algorithms;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use function Safe\base64_decode;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @group functional
 */
class AttestationTest extends KernelTestCase
{
    /**
     * @test
     */
    public function anAttestationResponseCanBeLoadedAndVerified(): void
    {
        self::bootKernel();

        $publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('My Application'),
            new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity'),
            base64_decode('9WqgpRIYvGMCUYiFT20o1U7hSD193k11zu4tKP7wRcrE26zs1zc4LHyPinvPGS86wu6bDvpwbt8Xp2bQ3VBRSQ==', true),
            [
                new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256),
            ],
            60000,
            [],
            new AuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            new AuthenticationExtensionsClientInputs()
        );

        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load('{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK","type":"public-key","rawId":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ"}}');

        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->getType());
        static::assertEquals(base64_decode('mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK', true), $descriptor->getId());
        static::assertEquals([], $descriptor->getTransports());

        $response = $publicKeyCredential->getResponse();
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        static::assertEquals(AttestationStatement::TYPE_NONE, $response->getAttestationObject()->getAttStmt()->getType());
        static::assertInstanceOf(EmptyTrustPath::class, $response->getAttestationObject()->getAttStmt()->getTrustPath());

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('localhost');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        self::$kernel->getContainer()->get(AuthenticatorAttestationResponseValidator::class)->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
    }

    /**
     * @test
     */
    public function anAttestationResponseCanBeLoadedAndVerified2(): void
    {
        self::bootKernel();
        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"WTDxpo5kkWJjtJ3ohDhpTWEx39ivkYt_c4xwHJgefUc","attestation":"direct","user":{"name":"BtpYiT5YeM0g0AvHIcqd","id":"MGQ2OGFkZDQtNjZiYy00NzY1LWJlOTctMWIzNmIyMmJjMjU1","displayName":"Freddie Montijo"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        $result = '{"id":"Y449VyCutqNSfYqIanYCnG_ERdnZ_bgfIPP8hT5i0iM","rawId":"Y449VyCutqNSfYqIanYCnG_ERdnZ_bgfIPP8hT5i0iM","response":{"attestationObject":"o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzkBAGNzaWdZAQBoKU879k-i-bG6_hrHxPktZ2r0lDoOcA1RmExoSFlJ2Z8NasTKES620i-q79eo5lGasEFM4FN-1dZypsbiZdFWYJ5hpbNRjuG8qFO7CReELVuGH8kXHifspf1rCQETTamx2kU4uK0BQoojVv57wK5t0hr1PXfKjIO7rCEJH1zKOYywmkb2_saJ1odIb1fbwjoGVrw41JCuOHyJn4snWd-khnGZli25LC9GeEWGKs0DdFVX0XvI6iYlpLg6IVcG8g5KRQCflSvzNFiOOn346Fp9PbnmTilxwGMJ22b8bfuHhdkJJbUNerZObDleRWog6cOLVoTaHD4Bq4x6rDJI-76pY3ZlcmMyLjBjeDVjglkEhzCCBIMwggNroAMCAQICDwRfumLFa6Y4qANCPY4RZjANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELTAzN0FGNzM4MTEwRjk2MDU0RENERjA4MkVGRkEwMzFGOUJGODEwQUYwHhcNMTgwMjAxMDAwMDAwWhcNMjUwMTMxMjM1OTU5WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIq0W2FetalcMPNXbagB9PlG5uMpK5s1AdGA4r-LivPMV0tpQrlBITMluhVwPIL0QDn2FNc7uudslujJRR3p-afkaeptk97Mpn7r6TFiHm-H4gna7P-wAAML58kxjJOApjVIJabyhS6w6oDkmHcU8pdz2h39ZRUD0mBug4OwJ3xS8cj8D1Dx6JTNqh5w1REpr9ZQDJxgOBAWjrf1fiXb0XuO2XO3taLI_dZGxZsovUXC94QeQIi0tADas89v3L9lR1ZcRuNj5s2nlnXrKtfAZdtFTEicUVmH9xgD_YiuxoE9ZGrDa0ZAuKmaMQQWw6ChIXFlqohFP1pZnxRwokxfnwIDAQABo4IBtzCCAbMwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwewYDVR0gAQH_BHEwbzBtBgkrBgEEAYI3FR8wYDBeBggrBgEFBQcCAjBSHlAARgBBAEsARQAgAEYASQBEAE8AIABUAEMAUABBACAAVAByAHUAcwB0AGUAZAAgAFAAbABhAHQAZgBvAHIAbQAgAEkAZABlAG4AdABpAHQAeTAQBgNVHSUECTAHBgVngQUIAzBKBgNVHREBAf8EQDA-pDwwOjE4MA4GBWeBBQIDDAVpZDoxMzAQBgVngQUCAgwHTlBDVDZ4eDAUBgVngQUCAQwLaWQ6RkZGRkYxRDAwHwYDVR0jBBgwFoAUUX8iyOZTpXzVTN0wWH4w_2c2jF0wHQYDVR0OBBYEFDVEHgiRA6Zs7ZvY5mep4iuPE7zgMHgGCCsGAQUFBwEBBGwwajBoBggrBgEFBQcwAoZcaHR0cHM6Ly9maWRvYWxsaWFuY2UuY28ubnovdHBtcGtpL05DVS1OVEMtS0VZSUQtMDM3QUY3MzgxMTBGOTYwNTREQ0RGMDgyRUZGQTAzMUY5QkY4MTBBRi5jcnQwDQYJKoZIhvcNAQELBQADggEBAFznNexHQnnvMe8yzXICp7o6dJV21_ULuDMK2OQbqPOSKOaBhbcl0H9kHGip3dw70nLvhnDZRqV9aTbPUXa9T3AcVHmlznYCmBq7zl977AxfG55jsVnjO8yalexQu9f_CKuNpXDhgyvlBPFl5MFudAalwl-u2oNVTFppdDLgUe4t1yyzmTXjjYPD5KbJo-k4I_gDblnb1M-pr-kPvHzAnstDHIVeqsVXdbFTwQ89uagoSKf3XGd21S6ljGR8b_j7JKBRJNlXpM9cffW-8LT5jz18feIyZS-xsXFoHYGra7RX0EPdmHDCW5g_KZ-Sh9vsw3SJNjKZsPQN77Yhpct-Mn9ZBgUwggYBMIID6aADAgECAg8Ea4iQoZL_Z7CuCmNqDHMwDQYJKoZIhvcNAQELBQAwgb8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxNjA0BgNVBAMMLUZJRE8gRmFrZSBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxODExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzAeFw0xNzAyMDEwMDAwMDBaFw0zNTAxMzEyMzU5NTlaMEExPzA9BgNVBAMTNk5DVS1OVEMtS0VZSUQtMDM3QUY3MzgxMTBGOTYwNTREQ0RGMDgyRUZGQTAzMUY5QkY4MTBBRjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANc-c30RpQd-_LCoiLJbXz3t_vqciOIovwjez79_DtVgi8G9Ph-tPL-lC0ueFGBMSPcKd_RDdSFe2QCYQd9e0DtiFxra-uWGa0olI1hHI7bK2GzNAZSTKEbwgqpf8vXMQ-7SPajg6PfxSOLH_Nj2yd6tkNkUSdlGtWfY8XGB3n-q--nt3UHdUQWEtgUoTe5abBXsG7MQSuTNoad3v6vk-tLd0W44ivM6pbFqFUHchx8mGLApCpjlVXrfROaCoc9E91hG9B-WNvekJ0dM6kJ658Hy7yscQ6JdqIEolYojCtWaWNmwcfv--OE1Ax_4Ub24gl3hpB9EOcBCzpb4UFmLYUECAwEAAaOCAXUwggFxMAsGA1UdDwQEAwIBhjAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzAbBgNVHSUEFDASBgkrBgEEAYI3FSQGBWeBBQgDMBIGA1UdEwEB_wQIMAYBAf8CAQAwHQYDVR0OBBYEFFF_IsjmU6V81UzdMFh-MP9nNoxdMB8GA1UdIwQYMBaAFFx_Ni2QrVq8uo512t46oO3BTgKLMGgGA1UdHwRhMF8wXaBboFmGV2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9jcmwvRklETyBGYWtlIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE4LmNybDBvBggrBgEFBQcBAQRjMGEwXwYIKwYBBQUHMAKGU2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9GSURPIEZha2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTguY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCN1i8OPMdt_K9yL8UI_SUx7NkEpDRQ-FWJ6-JNQIfpV8aTAPmDLiSqeSQEheq_F0s4RuiGQLkS3xRFFiIF9y5-ouiqyWMKJLVMNdhkMr1YJmBzkrcGYLEVl80WhtxoK_8QUpQpzqjpXjyJdVAi5nnbOvQ4gUuSDXD1BUynY3xAxn9Sn73QhKlgZSSxV65DsP3_VG4nZqQ_EnpiSP_QVIas6MR4F96N3NReQ2Qc9RAZ05xArnbZW32xCApSeAgUoWJiSYTOUdPW8whl05B0ni_PCgOn3QtVlMC3Zm0d7P8WXihpGtT24_h6q0ewBJKeXejcXW4gohHNtPfBCAKypTw_rsJrzsMk1SnzA5dJEyoTcz4_Yh_tRXjg9-pDuECqZrnb_Z3hDB0ctqPvSVwONhWkyrWgejExBfJ3i2oGlzihqcZ2VsTvsFostfRB2dRwm1JWoy63_39uZW48pkfI3JRXgNPHJWiH16Zz8Jb6jx2brOmyifTmMyhfgDkuwSYG5Wp2-hsORKTjRlzkEooi9n57GEGi8OIhe6a4l8ZeIee4C7DdTT7WZeIL2Muxg0bEDz63NiVdQBp6gJkbTzzgLfRDVPVwXfzxCwdp-uf2dw0QjTAQ8kecVW_AZ5Y5BWJHdWjWUMA9xFarDti1dAznGPZscrMNHEhhpmLmhxBL_Nk0kGdwdWJBcmVhWQE2AAEABAAGBHIAIJ3_y_NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi_rSKuABAAEAgAAAAAAAEArXFsoAQGAUXIBenPIFztxECVr8ldoCqlJkeN0BSG5ekSsE8DY0kDGlf2UizeC5AXH0oTCw_0saW53XBe6ewghp5lzxpAq4a5lyJv40Yis1YkX8YvtMf_Ic_kVsrqOK2iKm4NGtzK-t4iDj17Hh3sAOMg8RxuaJV-QU7PoVSbduzB0amktaqc5FNgZjnc_EbLBR7YvGGFBP3aGNomZurYFA8vVMDhw0qmOrA4iX2XGzKLd_YywouJQ_c9gkCP9N-Xo3S9oZlAW1pYvRDTuMdQ6DBikj802fjdcuIZpT4N6fyYFGeS8NP94-0l3j2Vpv0nZWku1kca7H6th29s49eo9WhjZXJ0SW5mb1it_1RDR4AXACIACxHmjtRNtTcuFCluL4Ssx4OYdRiBkh4w_CKgb4tzx5RTACDZLMfHrTF_lwAnrhF3IFiMvEqwtMdrnHnKZY7iBpANZgAAAAFHcBdIVWl7S8aFYKUBc375jTRWVfsAIgALezMaOCNoGuG34tNxgR4WQ5A5o4F-BKpPvxSi_wiXBykAIgAL4WlD31qwtzON1tYuOIv7vPS2CQQqxQLYf9KGJ9ZZPg1oYXV0aERhdGFZAWeWBOqCgk6YpK2hS0Ri0Nc6jsRpEw2pGxkwdFkin3SjWUEAAACUp9bZOooNEeialKbPcQcvcwAgY449VyCutqNSfYqIanYCnG_ERdnZ_bgfIPP8hT5i0iOkAQMDOQEAIFkBAK1xbKAEBgFFyAXpzyBc7cRAla_JXaAqpSZHjdAUhuXpErBPA2NJAxpX9lIs3guQFx9KEwsP9LGlud1wXunsIIaeZc8aQKuGuZcib-NGIrNWJF_GL7TH_yHP5FbK6jitoipuDRrcyvreIg49ex4d7ADjIPEcbmiVfkFOz6FUm3bswdGppLWqnORTYGY53PxGywUe2LxhhQT92hjaJmbq2BQPL1TA4cNKpjqwOIl9lxsyi3f2MsKLiUP3PYJAj_Tfl6N0vaGZQFtaWL0Q07jHUOgwYpI_NNn43XLiGaU-Den8mBRnkvDT_ePtJd49lab9J2VpLtZHGux-rYdvbOPXqPUhQwEAAQ","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IldURHhwbzVra1dKanRKM29oRGhwVFdFeDM5aXZrWXRfYzR4d0hKZ2VmVWMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load($result);

        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->getType());
        static::assertEquals(hex2bin('638e3d5720aeb6a3527d8a886a76029c6fc445d9d9fdb81f20f3fc853e62d223'), $descriptor->getId());
        static::assertEquals([], $descriptor->getTransports());

        $response = $publicKeyCredential->getResponse();
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        static::assertEquals(AttestationStatement::TYPE_ATTCA, $response->getAttestationObject()->getAttStmt()->getType());
        static::assertInstanceOf(CertificateTrustPath::class, $response->getAttestationObject()->getAttStmt()->getTrustPath());

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.spomky-labs.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        self::$kernel->getContainer()->get(AuthenticatorAttestationResponseValidator::class)->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
    }

    /**
     * @test
     */
    public function aFullCertificateChainShouldNotBeUsedForThisSelfAttestation(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid attestation statement. The attestation type is not allowed for this authenticator');

        self::bootKernel();
        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"h8lQZpu-S0rTLOOeAr7BeWoPPTkhtqcEzlHizEyzVeQ","attestation":"direct","user":{"name":"fwOcfew16ujF_p7Hl5eh","id":"ZTc4N2YzZmItMDgwZS00ZDNjLTlhZDItYmE3OTAwYTVlNTg1","displayName":"Gretchen Mo"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        $result = '{"id":"icUOVRPT8oO9WQhpaE90z6jlKCac8JdnczpH6t694JQ","rawId":"icUOVRPT8oO9WQhpaE90z6jlKCac8JdnczpH6t694JQ","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgZrOe5oDaahYFZM1iH9P_NJpbwN1FY0swi0d8pGImrwYCIBggQ17iKyGOnqVYumhwL_escFlB27AETQl0yLO8nmuWY3g1Y4FZBEUwggRBMIICKaADAgECAgEBMA0GCSqGSIb3DQEBCwUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzOTQzWhcNMjgwNTIwMTQzOTQzWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETzpeXqtsH7yul_bfZEmWdix773IAQCp2xvIw9lVvF6qZm1l_xL9Qiq-OnvDNAT9aub0nkUvwgEN4y8yxG4m1RqMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUVk33wPjGVbahH2xNGfO_QeL9AXkwDQYJKoZIhvcNAQELBQADggIBAIfdoJ_4IIkF0S1Bzgmk6dR6XAYbDsPGcEyiQccGCvMnEOf0EVwXDEYvGsVXsR9h6FA04P7vg5Lx9lGBmI1_0QMYBiIeHT4Kyl8FZ3bTMIiOUJ0MFzKHCrc8snrkkL-iDcJP0AriS-SzgMj7TVFjE2_1LwnHWFo7WWBTnmEEivU_-nbVkqelwISE-MH9wgWscmovmIkZ9534teeL1K6rbg4eenjgyu_iHs4PZ6W7nJZ918Vv5EYbZNhREUgZgaKOyKLT3fDRkwE58FL7der8Osd5ltmus2RjjnmAkJnl5Xzc2u30n39QXRVkeX-HCdIBQL9ve03-XRmUL2Q9w3MkPTiXid0UEPYp19DYcZNfunJtYtnvIfYEze6LY6mJpxo7N3s4T3WsdgHa5nJDuN2DbnIX0zxAj00cz-K0KN0G8Bi3hAJPx1fqCZmIgZHYX9hdkCzJu0nXqmdSY4NVtbzSU9vPL49RBhfv2il4P27owGivOv2DTwSWlvUXcOBJ3xVIuWxHZA-WUqXgBwkMwg59kc5AY7Nq0xXuKkRVFrQvkWeMBakce9I1yyMPgK6XnraY7cyUjakLKj5RL6cjMbldmY567gNv8rD90Q86jbO0fCVTSoontEQGxu3reN1C2XAu6IsfCSmLCesA5l_Bssu71jPi0vV4mVB9-7BL8CiWzPscaGF1dGhEYXRhWKSWBOqCgk6YpK2hS0Ri0Nc6jsRpEw2pGxkwdFkin3SjWUEAAABTKy7LtFm0RPqGjaBySF2K4AAgicUOVRPT8oO9WQhpaE90z6jlKCac8JdnczpH6t694JSlAQIDJiABIVgg_YaefIjxYBFvUYvXdQCxl-2AbCSIAOCwxt_m_qQ-SeEiWCBiSYa6JD1eR7jbJOppgUdyIle1hmviAK-UvU7_-SZbCg","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6Img4bFFacHUtUzByVExPT2VBcjdCZVdvUFBUa2h0cWNFemxIaXpFeXpWZVEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load($result);

        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->getType());
        static::assertEquals(hex2bin('89c50e5513d3f283bd590869684f74cfa8e528269cf09767733a47eadebde094'), $descriptor->getId());
        static::assertEquals([], $descriptor->getTransports());

        $response = $publicKeyCredential->getResponse();
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        static::assertEquals(AttestationStatement::TYPE_BASIC, $response->getAttestationObject()->getAttStmt()->getType());
        static::assertInstanceOf(CertificateTrustPath::class, $response->getAttestationObject()->getAttStmt()->getTrustPath());

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.spomky-labs.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        self::$kernel->getContainer()->get(AuthenticatorAttestationResponseValidator::class)->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
        static::assertTrue(false);
    }

    /**
     * @test
     */
    public function b1(): void
    {
        self::bootKernel();
        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"NZCC4S63bleWmi4T9NCHRF6OcIwSd2JCgfsD-wbKJlc","attestation":"direct","user":{"name":"hn4xNFsaQM9sfpxVY3N6","id":"ZTBlMWQzNzEtNmRlMS00NzQ1LWJiZjQtNGFlMmVlMDYyOGNj","displayName":"Aleisha Neyman"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000}';
        $result = '{"id":"ZN5rdouKy5zUhRwOJIcBEEk6PyD4zhufi6mKKYJuvQ8","rawId":"ZN5rdouKy5zUhRwOJIcBEEk6PyD4zhufi6mKKYJuvQ8","response":{"attestationObject":"o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDEyNjg1MDIzaHJlc3BvbnNlWRWVZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHVDJwRFEwSkRTMmRCZDBsQ1FXZEpVRUpJYkVSUVdrTTBNRUZ4Y0hGd01DdGxiVE40VFVFd1IwTlRjVWRUU1dJelJGRkZRa04zVlVGTlJ6UjRRM3BCU2tKblRsWkNRVmxVUVd4V1ZFMVRjM2RMVVZsRVZsRlJTMFJEU2tkVFZWSlFTVVZHYzJKSGJHaGliVTVzWTNsQ1IxRlZkRVpKUmxKNVpGaE9NRWxHVG14amJscHdXVEpXZWsxVVNYZE5RVmxFVmxGUlJFUkRiRWRUVlZKUVNVVkdjMkpIYkdoaWJVNXNZM2xDUjFGVmRFWkpSV3gxWkVkV2VXSnRWakJKUlVZeFpFZG9kbU50YkRCbFUwSkhUVlJCWlVaM01IaFBSRUY1VFVSRmQwMUVRWGROUkVKaFJuY3dlVTFFUVRSTlJHTjRUMVJKTlUxNlRtRk5TRVY0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFSYzNkRFVWbEVWbEZSU1VSQlNrNVhWRVZUVFVKQlIwRXhWVVZDZDNkS1ZqSkdjbHBYV25CYVYzaHJUVkpaZDBaQldVUldVVkZMUkVFeFIxTlZVbEJKUlVaellrZHNhR0p0VG14TlVYZDNRMmRaUkZaUlVVeEVRVTVFVmpCamVFZDZRVnBDWjA1V1FrRk5UVVZ0UmpCa1IxWjZaRU0xYUdKdFVubGlNbXhyVEcxT2RtSlVRME5CVTBsM1JGRlpTa3R2V2tsb2RtTk9RVkZGUWtKUlFVUm5aMFZRUVVSRFEwRlJiME5uWjBWQ1FVMXlWbmhyVjNCdlFuTm1NMkozUlRBNGRGUmxlVU5yV2s1UU9VUnlabUptYlZJMUx5OUpVazVNT1c1dVRtZEVSbXhLY1hFeFMybERTVVpyUlROQk5WZzFiMnRoUjBJeU5UTnNPVUZqUVdoeFVVNXFORGRTYTBOSWNHTTJiR3AwZW5SVWNXeFpiVkF3WkVOa2MzaHVka2xCZDJ4TmJHd3pLM0pLYzIxbGRsWk5abmRqUjJoamFWaEVaR3RPT0ZONlowbDJkU3RKVnpCcmRuSkRhVWhqVmxBMFdHazBNazlwVDB4NVVIUldZVVUyZG5VNFVrbE9UbnBJZW05ck5HMDNaa0pQU1hreWEwY3hUMUpRTlRCUGJuaEhTRlo2V1hGM2FtOUxWMkpWTUZSc1IxRlFVVWROYW5jck1URlFaaTlDTDBWdFZtSjNVRlJWUm00cllUTlBVak51U0hacE4zTlBlWFJKTkdNemMzQnBORUpLTTNwalIzVlJWVXR5Um1wV0t6Wk9lVXhxY2xORlMySjNVWGhPUWpsR1UyNVVhemt2VG14R1VWUXlLMWR1VFZKV1UybGFVMklyZUhsaGNURkJRMGN2TWs1SFZVTkJkMFZCUVdGUFEwRmtRWGRuWjBoTlRVTkZSMEV4VldSSlFWRmhUVUpuZDBSQldVdExkMWxDUWtGSVYyVlJTVVpCZWtGSlFtZGFibWRSZDBKQlowbDNSWGRaUkZaU01HeENRWGQzUTJkWlNVdDNXVUpDVVZWSVFYZEZkMFJCV1VSV1VqQlVRVkZJTDBKQlNYZEJSRUZrUW1kT1ZraFJORVZHWjFGVmJtNXFSM1UwVVc5R01uTjNVblpKT0Zad2RWRlJXVGtyYTFWemQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWdk9XOVlORWxuTURJNGJXMVlRVU5SVXpGemMwbENVVVE1VVdOM1ZYZFpSRlpTTUdaQ1JYZDNVMnBDU1c5RllXZFNTVnBEWVVoU01HTklUVFpNZVRsdFlWZFNkbGxYZUhOaFYwWjFXVEpWZFZreU9IVmlibTkyWXpKR2JWcFlValZpYlZZd1kwZDBjRXd5VG5saVF6bG9aRWhTYkdNelVYVlpWelZyWTIwNWNGcEROV3BpTWpCMVdUTktjMDFKU0hWQ1oyZHlRbWRGUmtKUlkwSkJVVk5DTkZSRFFqTnFRbkpDWjJkeVFtZEZSa0pSWTNkQmIxcG1ZVWhTTUdOSVRUWk1lVGx0WVZkU2RsbFhlSE5oVjBaMVdUSlZkVmt5T0hWaWJtOTJZekpHYlZwWVVqVmliVll3WTBkMGNFd3dXa3BTUlRoc1RXcENSMWxYZEd4S1ZFbDNWVzA1ZG1SRFZYbE5SVTVzWTI1U2NGcHRiR3BaV0ZKc1NsUkpkMUZZVmpCaFJ6bDVZVmhTTlVwVVNYZE5ha0Y0VDBNMWFtTnVVWGRpZDFsSlMzZFpRa0pSVlVoTlFVZEhXVEpvTUdSSVFucFBhVGgyV20xc2EySXlSbk5pUjJ4b1ltMU9iRXh0VG5aTWJUVTJURE5PYUZwdFZqQmxWelZzWkVoQ2NtRlRPV3BqYlhkMlVtdHNSVlI1VlhsTlJWcG9ZVEpWYkUxcVFsTmlNamt3U2xSSmQxRXlWbmxrUjJ4dFlWZE9hR1JIVld4TmFrSkNaRmhTYjJJelNuQmtTR3RzVFdwQmVVMUVSVFJNYlU1NVlrUkJUa0puYTNGb2EybEhPWGN3UWtGUmMwWkJRVTlEUVZGRlFXTlNMMXBTV2tRMmJsVlBZMkkzWVhVM2VVdHNXblZCVDFOeFpXUldObmxoZVRKT2FVMDNZak42VkZvNFRGRnpiR056ZDFGeFYyazJPVlpWYURac1dYUjFRM05TZW05NWFuaFBSRU5aTkhKbFRHdE9jVmxNZWxKcGRtcElXSFJPV0cxbE1rOTJNVlJrTUVGeWNIZEdTRUl6UjFJMFRHNXdkbVZXUm5kbWR6RmxSVU40SzIxMFJ6bGtlSFk1VWpsc1prNTJORkE1UVZoWFdGaEdUMWRGU1N0a1IxQnNLMk5vZGxCaGREUlJZbEIyWms5WmEwZFRTV3RxZFdweFNuSlZla0pPZHpWelYza3ZkMnN3YW14RmQxVmFPRGh2V2l0WmFTOXphWFJWVjJJdlRsWm9kREpUZDNaWFNTOVhaMUJXYjJSamVuRm9URVF2U1V3NWVWQjBNVTFhZFVGVVNIcHdVRXM1ZEVKYVFVOTBNekV6WkhSSFJXSmlZVE5xYkZoNk1IZHlZa2xLTVhKTmJEUXlRVzlZVmt4c1ZGSXphRWt2VTBwbU1GUkZVVGhSTlVwdGJtaGpNMlJ0UTBwRFVWZEJkMlIxTmxsRWR6MDlJaXdpVFVsSlJrUlVRME5CTDFkblFYZEpRa0ZuU1ZCQ1RtWlFWbnBUVG5aaVMwOUhNR1ZIUW5WRlNrMUJNRWREVTNGSFUwbGlNMFJSUlVKRGQxVkJUVVpCZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOVWxsM1JrRlpSRlpSVVV0RVFURkhVMVZTVUVsRlJuTmlSMnhvWW0xT2JFMVRhM2RLZDFsRVZsRlJSRVJEUWtkVFZWSlFTVVZHYzJKSGJHaGliVTVzWTNsQ1IxRlZkRVpKUmtwMllqTlJaMUV3UldkTVUwSlVUVlJCWlVaM01IaE9la0Y1VFVSRmQwMUVRWGROUkVKaFJuY3dlazVVUVhoTmVrVjVUWHBWTlU1VWJHRk5SelI0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFUYzNkTFVWbEVWbEZSUzBSRFNrZFRWVkpRU1VWR2MySkhiR2hpYlU1c1kzbENSMUZWZEVaSlJsSjVaRmhPTUVsR1RteGpibHB3V1RKV2VrMVVTWGROUVZsRVZsRlJSRVJEYkVkVFZWSlFTVVZHYzJKSGJHaGliVTVzWTNsQ1IxRlZkRVpKUld4MVpFZFdlV0p0VmpCSlJVWXhaRWRvZG1OdGJEQmxVMEpIVFZSRFEwRlRTWGRFVVZsS1MyOWFTV2gyWTA1QlVVVkNRbEZCUkdkblJWQkJSRU5EUVZGdlEyZG5SVUpCVFVWSWJVWm1ZazU1Y0ZCMWNUazBheXRUVTBOcFZYWllVM1Z0YjJ4WmNFaFpTR2xyVUdGV01tcFJZbUpZZGtkMVNpdDNPSGw0ZWtoSFZWSkdXbEZNWmtOR1ZuSlVXakkyT1dWaWRsa3ljRTVzYUZWVGNFNUtZemRUY0dodmJGTnlPWFJEYW5WSVpFZE1NM1YyUW1Sd2VHRmFhblowWkZaRk5ubHVOVnAyUTNoNWVDOW9RV2QxUldSclpGQjFWa1Z0WkZaRWNqWTBZelk0WkRJNGIya3ZNMWx6Um01SlluRk5iblZZZGpod2NYWkdZWE5IYW1SVVYwWkRNMkYxU2tka2RUSjJOalZ6UWxVMGRsZGpja1ZHWkZscU1FMW5kMDlFTUd4dldVaGlLekI2UzBzNWQzaG1hVnBRVlZZNFNFVmFZa3QzUkZkbU5XcHZkV0ZqU21WWFdqTXlORmRHTVV4SVQycFhjbmhJWjI5RVVVSnBlbk15Y1ZWR1NuWkRUbWx1YzJGRFUwMDFTbE40VVhWc1RVZGtZa1JWVlZOMldUTnVhV3Q2Ym5KNVRuSk9ObVl2VDFKdVptc3lLMHRKZW5SamRESnJUMGxqUTBGM1JVRkJZVTlEUVdOUmQyZG5TRUZOUVhOSFFURlZaRVIzVVVWQmQwbENhR3BDVEVKblRsWklVMEZGVWtSQ1EwMUZRVWRDYldWQ1JFRkZRMEZxUVRKTlJGRkhRME56UjBGUlZVWkNkMGxDUm1sb2IyUklVbmRqZW05MlRESmFjRnBIT1doaVIzaHdXVmMxYWxwVE5XcGllVFYxWldrNWVsbFhXbXhrU0d4MVdsaFNkMkV5YTNaTlFqQkhRVEZWWkVwUlVWZE5RbEZIUTBOelIwRlJWVVpDZDAxQ1FtZG5ja0puUlVaQ1VXTkVRV3BCVTBKblRsWklVazFDUVdZNFJVTkVRVWRCVVVndlFXZEZRVTFDTUVkQk1WVmtSR2RSVjBKQ1Uyb3lhR1puYVVSVVlubGhXbU5CU2tKTVYzbDNaMFpCVURGQ2VrRm1RbWRPVmtoVFRVVkhSRUZYWjBKVGNVNTJPVUpoWkV0a2FXcDJXVWhIV0ZSWE9UVnlZME15Vld0RVFqQkNaMDVXU0ZJNFJXSlVRbkpOUjIxbldqWkNiR2h0VG05a1NGSjNZM3B2ZGt3eVduQmFSemxvWWtkNGNGbFhOV3BhVXpWcVluazFkV1ZwT1hwWlYxcHNaRWhzZFZwWVVuZGhNbXQyV1ROS2Mwd3dXa3BTUlRoc1RXcENSMWxYZEd4S1ZFbDNWVzA1ZG1SRFZYbE5SVTVzWTI1U2NGcHRiR3BaV0ZKc1NsUkpkMUZZVmpCaFJ6bDVZVmhTTlVwVVNYZE5ha0Y0VDBNMWFtTnRkM2RsZDFsSlMzZFpRa0pSVlVoQlVVVkZZbnBDZEUxSGMwZERRM05IUVZGVlJrSjZRVUpvYkRsdlpFaFNkMk42YjNaTU1scHdXa2M1YUdKSGVIQlpWelZxV2xNMWFtSjVOWFZsYVRsNldWZGFiR1JJYkhWYVdGSjNZVEpyZGxKcmJFVlVlVlY1VFVWYWFHRXlWV3hOYWtKVFlqSTVNRXBVU1hkUk1sWjVaRWRzYldGWFRtaGtSMVZzVFdwQ1FtUllVbTlpTTBwd1pFaHJiRTFxUVhsTlJFVTBURzFPZVdSRVFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGcFQwOUlNRmxCSzNFdldVZERXVGM1YTJaTFZTOWFVV3BpU3pCTmMxSjNRM3BhUnpsVEwyMDBhWGRKWTNwUk0wZGhhMDlHU0RkeWVUUjVSbkZSTlRoalR5czVaMkpXY25OQ2FFZzFORUpKTUUxM1V6VnBRMWhxYUhZeFltZHJNVWhzZEhjNFMwaFNiM05zU25KNVJGRlFlbEl6VXpKRlRYWjRLMng2ZURKWWRqWnpNbGg0ZGtoU1VrTTRTMUZaVkM5UFYyUm1hVGxEWmtJNVpGRnZTMk5rYlRWc01XWkVPV2RXVmpadGVHVjZhM0pSYkRkRE1FdG1aVFJhY0hreE5EZElUMjlhTURSeVQzaHNlSFIwTTFkSWMwWm5WMHd2VFc0d1pHSmlRVk13ZUhoRFRtUjNPRGhKYVV4T04wZDZTM3BTY21KM05tTkljMEpFWVhaNGJGaEdZMHAxT0ZaeFUycE9UVkpHUkVneFVEUkJSMkpUWlZnNGVYVkVNV2R6TjNkMmJISkJlV1J2VEhaeE5qZFFVREkwZDFVMFFqRjFVVmx1V1VWdFF6VnZRWFp6Tm5GVGRteHdkRVJpVG5NM1kyaE5lVEJoY0hjOVBTSmRmUS5leUp1YjI1alpTSTZJa2hUTlVwcE4wTmlhM0JHZERSeVVGcGpUVFJMTWt4UWRsRkZMMnBvTDNsVk1tNUpRUzlXVm1wNU5XTTlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFOalV5TURZeE56TXhOamtzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtRnVaSEp2YVdRdWEyVjVjM1J2Y21VdVlXNWtjbTlwWkd0bGVYTjBiM0psWkdWdGJ5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbVJOTDB4VlNGTkpPVk5yVVdoYVNFaHdVVmRTYm5wS00wMTJka0l5UVU1VFlYVnhXVUZCWWxNeVNtYzlJaXdpWVhCclEyVnlkR2xtYVdOaGRHVkVhV2RsYzNSVGFHRXlOVFlpT2xzaVluTmlOQzlYVVdSaFlVOVhXVU5rTDJvNVQwcHBVWEJuTjJJd2FYZEdaMEZqTDNwNlFURjBRMlozUlQwaVhTd2lZM1J6VUhKdlptbHNaVTFoZEdOb0lqcDBjblZsTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC53UmZYVUFKU1l6Qi01VTIzMlB1RlJjTW9mTklUbi1FSUNBOGFKWDhycEUzdEF0OUpaem9oRlhRYTZ3OXVOQ3hwRXpDYTBOTWNCODlicE5QNTNOdVRVcFNBUC1wNklVMUtKNnRaMWN3dnBoUEw1dmRHSUwtaFZsWm0zSlVITjViVTBmSXZLUExjSkFpTlNwRmpSV1IxRmlucWJnV29SY0pGSnBZZzE3YUVKRDdTbkRLcEpnckZZdW5GWURzOTNiMDZnTEVKZXpaX2F0Q0E3NW9qOGJWUEE3ZVhzcmpYUGJwWDZScXlEbHZLUFZKRnZzX1Vvb20wQ0dMTjdNcktqbXJFa0xSR0I4M0U4U18zZlpXdk9QX3ZNTVhVRG52RlpQWlg1LUdmQURIZUVDa1ZBQVpZTXVTd2V6NEpnaG5XTFRiamtZdWx2dGd2UDY4TDBMZXVnc2t1VndoYXV0aERhdGFZAWeWBOqCgk6YpK2hS0Ri0Nc6jsRpEw2pGxkwdFkin3SjWUEAAAB-yHzdl1bBSbieJMs2NlTzUAAgZN5rdouKy5zUhRwOJIcBEEk6PyD4zhufi6mKKYJuvQ-kAQMDOQEAIFkBAO1lkEyxNXld2YZwqzDOpeunkyK6PBKvAomD6Z_LRoIDD0xqAsg1h2Tnbqz3FqP3dp7aKzRDnkQ8ylXzHanW7cIR1yYZ7uh6a08lF9oRUfZchhT1SCiMbFZiSDEm83t-zRvsYBUYy_j-d8cKVRzkNgMY8yZkmuB8XQU_yHCNzWrY2PFaGm9Bw2CsWxqbaYRHMffRmU_Hjc788WCPFH9tmfFwFVh-RlRS5TYbq-mgOcCTCBzD5mplV6tJ2hfocnxu_NzTVs_h-gzVIgGzc-GLhT_6hnPIfHaZijgy-5F9nj36x0SogqMTiwnk-fL3w0rWrAqaHKbz8TkM3Qdb_9itrP0hQwEAAQ","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6Ik5aQ0M0UzYzYmxlV21pNFQ5TkNIUkY2T2NJd1NkMkpDZ2ZzRC13YktKbGMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load($result);

        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->getType());
        static::assertEquals(hex2bin('64de6b768b8acb9cd4851c0e24870110493a3f20f8ce1b9f8ba98a29826ebd0f'), $descriptor->getId());
        static::assertEquals([], $descriptor->getTransports());

        $response = $publicKeyCredential->getResponse();
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        static::assertEquals(AttestationStatement::TYPE_BASIC, $response->getAttestationObject()->getAttStmt()->getType());
        static::assertInstanceOf(CertificateTrustPath::class, $response->getAttestationObject()->getAttStmt()->getTrustPath());

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.spomky-labs.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        self::$kernel->getContainer()->get(AuthenticatorAttestationResponseValidator::class)->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
    }

    /**
     * @test
     */
    public function c1(): void
    {
        self::bootKernel();
        $options = '{"status":"ok","errorMessage":"","rp":{"name":"Webauthn Demo","id":"webauthn.spomky-labs.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-43},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39}],"challenge":"BAK8koxXlFT07PjpW2rBhdg0iO5SsWIPUDpxwt7RkFY","attestation":"direct","user":{"name":"EEcujzftXuSQxt1cr0m-","id":"OTQ5NTk4NGUtYmI0NS00MmZiLWFmYzEtMWU3YWY4NDI3YzFl","displayName":"Commander Shepard"},"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"},"timeout":60000} ';
        $result = '{"id":"DMKtmWAP8EW2CBOpmmamxO4ON8yNt5q2udPoNzPdKIA","rawId":"DMKtmWAP8EW2CBOpmmamxO4ON8yNt5q2udPoNzPdKIA","response":{"attestationObject":"o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDEyNjg1MDIzaHJlc3BvbnNlWRWVZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHVDJwRFEwSkRTMmRCZDBsQ1FXZEpVRUpOYnpSeFF6ZG1kVVJFZEN0RVRrNDRVa3RMVFVFd1IwTlRjVWRUU1dJelJGRkZRa04zVlVGTlJ6UjRRM3BCU2tKblRsWkNRVmxVUVd4V1ZFMVRjM2RMVVZsRVZsRlJTMFJEU2tkVFZWSlFTVVZHYzJKSGJHaGliVTVzWTNsQ1IxRlZkRVpKUmxKNVpGaE9NRWxHVG14amJscHdXVEpXZWsxVVNYZE5RVmxFVmxGUlJFUkRiRWRUVlZKUVNVVkdjMkpIYkdoaWJVNXNZM2xDUjFGVmRFWkpSV3gxWkVkV2VXSnRWakJKUlVZeFpFZG9kbU50YkRCbFUwSkhUVlJCWlVaM01IaFBSRUY1VFVSRmQwMUVRWGROUkVKaFJuY3dlVTFFUVRSTlJHdDNUbFJKZUUxNmJHRk5TRVY0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFSYzNkRFVWbEVWbEZSU1VSQlNrNVhWRVZUVFVKQlIwRXhWVVZDZDNkS1ZqSkdjbHBYV25CYVYzaHJUVkpaZDBaQldVUldVVkZMUkVFeFIxTlZVbEJKUlVaellrZHNhR0p0VG14TlVYZDNRMmRaUkZaUlVVeEVRVTVFVmpCamVFZDZRVnBDWjA1V1FrRk5UVVZ0UmpCa1IxWjZaRU0xYUdKdFVubGlNbXhyVEcxT2RtSlVRME5CVTBsM1JGRlpTa3R2V2tsb2RtTk9RVkZGUWtKUlFVUm5aMFZRUVVSRFEwRlJiME5uWjBWQ1FVeGlRa1JpUkZoeFNUQTNPWFUwZUhSV09EUlVObkphU1RGSFYzRTJjMGRJVmtOcVEyeDFiVXB4U0dkdloxTkNNM3AwT0ZaUVRqWlpURWR4YjJGNmJHUXhVVlZXZUhsUGVIazFkMWh6WkhOS1YwdGtOV2hvUmtGeGFFWjRPVk0xVGpOT1dEbGpXVGxoYjNKck16Qk5iMkpUTTBKMWJTczRiRUo0V1VOS05qVk5ZMWxxVkU1UVRHeExNbFpNVjBoRVlscElTeTg1ZVRaak5rbGhZVU5YUm5kMFlrVktUVk5FY2xSaU9XMXphakZwVTJaVU9HUmtSMG94UlhJd2VGZFBWazVJYURscFJreERNbVZxYjB4RlRYTkJZMUlyZDFKdVZXVkxTREJxZVhsRlJETlhOWGxUYVdwelpWTXZOVE5YYm1ka1MwMVVNM0JPY2s5YUszaGpVRTV1Wm10dlYwTXhOWGRLYjFjME5qaFZOM2hGWTI5alYwUlRWVVp4ZVU4eE5tUnBWVUk0Y2paTmNFWmhhbVZNT1hGb09GRkZkMUlyY0hBNU0zSXhNVEJ3TTBWaVkxRmtZMUZrVTFGemVYYzRXV3BJY1VSTU9FTkJkMFZCUVdGUFEwRmtRWGRuWjBoTlRVTkZSMEV4VldSSlFWRmhUVUpuZDBSQldVdExkMWxDUWtGSVYyVlJTVVpCZWtGSlFtZGFibWRSZDBKQlowbDNSWGRaUkZaU01HeENRWGQzUTJkWlNVdDNXVUpDVVZWSVFYZEZkMFJCV1VSV1VqQlVRVkZJTDBKQlNYZEJSRUZrUW1kT1ZraFJORVZHWjFGVlRWbGxTRVZtUlVwb1QweG5VMEU0VUhCc2FtWnBWMnhsWTNKamQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWUVUxZHllRU4zUmxCVVFrSnBVVlp3VkRKWksyaHlUVzFsWTBWM1ZYZFpSRlpTTUdaQ1JYZDNVMnBDU1c5RllXZFNTVnBEWVVoU01HTklUVFpNZVRsdFlWZFNkbGxYZUhOaFYwWjFXVEpWZFZreU9IVmlibTkyWXpKR2JWcFlValZpYlZZd1kwZDBjRXd5VG5saVF6bG9aRWhTYkdNelVYVlpWelZyWTIwNWNGcEROV3BpTWpCMVdUTktjMDFKU0hWQ1oyZHlRbWRGUmtKUlkwSkJVVk5DTkZSRFFqTnFRbkpDWjJkeVFtZEZSa0pSWTNkQmIxcG1ZVWhTTUdOSVRUWk1lVGx0WVZkU2RsbFhlSE5oVjBaMVdUSlZkVmt5T0hWaWJtOTJZekpHYlZwWVVqVmliVll3WTBkMGNFd3dXa3BTUlRoc1RXcENSMWxYZEd4S1ZFbDNWVzA1ZG1SRFZYbE5SVTVzWTI1U2NGcHRiR3BaV0ZKc1NsUkpkMUZZVmpCaFJ6bDVZVmhTTlVwVVNYZE5ha0Y0VDBNMWFtTnVVWGRpZDFsSlMzZFpRa0pSVlVoTlFVZEhXVEpvTUdSSVFucFBhVGgyV20xc2EySXlSbk5pUjJ4b1ltMU9iRXh0VG5aTWJUVTJURE5PYUZwdFZqQmxWelZzWkVoQ2NtRlRPV3BqYlhkMlVtdHNSVlI1VlhsTlJWcG9ZVEpWYkUxcVFsTmlNamt3U2xSSmQxRXlWbmxrUjJ4dFlWZE9hR1JIVld4TmFrSkNaRmhTYjJJelNuQmtTR3RzVFdwQmVVMUVSVFJNYlU1NVlrUkJUa0puYTNGb2EybEhPWGN3UWtGUmMwWkJRVTlEUVZGRlFXRndTVVowUzBWVldGVkdWRWRIYTNoUFkzWlVXblZxYXpWeGRIZ3lMMWMzTjBwcUsxUkNNRGxXTHk5b1ozcHJNMHQ2WkVoWUwwTllibEYzSzNSM1psUndZa0ZVY1UweU5HZFBVMWxuUzFCaFVsQkxOV1ZSZUdacU5sSTJjVmM1YXpRd1QwTnNNR0pET0RBelJrUnViSEIwTUZSNWMwSk5UMGxwZUhOcVp6UkVPRFYxV204MldteEtRVU5xSzJkVE9VMUNaamRLUVRaQlExUlRlWFl6YURGRVpETjBZMFpLYWtORk9HWlBjVWhOVHpFMlNYSXlZak5wYmt0WU9FcENZalZUWVZndmFrVkxkVm93TUdsc2VUUnhTVXBpZFZnMFNrMUhVWE5MTWxsS1kxTllXWEpGWkVWVkwyczJjMjlvTUdaNVZIaEJiVmQxYWxWcFltY3plQzkyYVd3NFp6VkhNVEZHVEVwbmJuazFVMms1ZEVSNFVrNVhTREJqVVc5cmJ5dDVTamhOWldOTWRHSXZUMFZEVTNRMll6ZEZSMlI2VkROVVZpdHVkMWxoVlc1TUwzZzRSbU0yWVd4RlZXazBaa2t3WjNoMVp6MDlJaXdpVFVsSlJrUlVRME5CTDFkblFYZEpRa0ZuU1ZCQ1RXRXllSGhaVFVsd1pYZ3ZNMk1yZG5GNmJFMUJNRWREVTNGSFUwbGlNMFJSUlVKRGQxVkJUVVpCZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOVWxsM1JrRlpSRlpSVVV0RVFURkhVMVZTVUVsRlJuTmlSMnhvWW0xT2JFMVRhM2RLZDFsRVZsRlJSRVJEUWtkVFZWSlFTVVZHYzJKSGJHaGliVTVzWTNsQ1IxRlZkRVpKUmtwMllqTlJaMUV3UldkTVUwSlVUVlJCWlVaM01IaE9la0Y1VFVSRmQwMUVRWGROUkVKaFJuY3dlazVVUVhoTmVrVjVUWHBWTlU1VWJHRk5SelI0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFUYzNkTFVWbEVWbEZSUzBSRFNrZFRWVkpRU1VWR2MySkhiR2hpYlU1c1kzbENSMUZWZEVaSlJsSjVaRmhPTUVsR1RteGpibHB3V1RKV2VrMVVTWGROUVZsRVZsRlJSRVJEYkVkVFZWSlFTVVZHYzJKSGJHaGliVTVzWTNsQ1IxRlZkRVpKUld4MVpFZFdlV0p0VmpCSlJVWXhaRWRvZG1OdGJEQmxVMEpIVFZSRFEwRlRTWGRFVVZsS1MyOWFTV2gyWTA1QlVVVkNRbEZCUkdkblJWQkJSRU5EUVZGdlEyZG5SVUpCVFVWSWJVWm1ZazU1Y0ZCMWNUazBheXRUVTBOcFZYWllVM1Z0YjJ4WmNFaFpTR2xyVUdGV01tcFJZbUpZZGtkMVNpdDNPSGw0ZWtoSFZWSkdXbEZNWmtOR1ZuSlVXakkyT1dWaWRsa3ljRTVzYUZWVGNFNUtZemRUY0dodmJGTnlPWFJEYW5WSVpFZE1NM1YyUW1Sd2VHRmFhblowWkZaRk5ubHVOVnAyUTNoNWVDOW9RV2QxUldSclpGQjFWa1Z0WkZaRWNqWTBZelk0WkRJNGIya3ZNMWx6Um01SlluRk5iblZZZGpod2NYWkdZWE5IYW1SVVYwWkRNMkYxU2tka2RUSjJOalZ6UWxVMGRsZGpja1ZHWkZscU1FMW5kMDlFTUd4dldVaGlLekI2UzBzNWQzaG1hVnBRVlZZNFNFVmFZa3QzUkZkbU5XcHZkV0ZqU21WWFdqTXlORmRHTVV4SVQycFhjbmhJWjI5RVVVSnBlbk15Y1ZWR1NuWkRUbWx1YzJGRFUwMDFTbE40VVhWc1RVZGtZa1JWVlZOMldUTnVhV3Q2Ym5KNVRuSk9ObVl2VDFKdVptc3lLMHRKZW5SamRESnJUMGxqUTBGM1JVRkJZVTlEUVdOUmQyZG5TRUZOUVhOSFFURlZaRVIzVVVWQmQwbENhR3BDVEVKblRsWklVMEZGVWtSQ1EwMUZRVWRDYldWQ1JFRkZRMEZxUVRKTlJGRkhRME56UjBGUlZVWkNkMGxDUm1sb2IyUklVbmRqZW05MlRESmFjRnBIT1doaVIzaHdXVmMxYWxwVE5XcGllVFYxWldrNWVsbFhXbXhrU0d4MVdsaFNkMkV5YTNaTlFqQkhRVEZWWkVwUlVWZE5RbEZIUTBOelIwRlJWVVpDZDAxQ1FtZG5ja0puUlVaQ1VXTkVRV3BCVTBKblRsWklVazFDUVdZNFJVTkVRVWRCVVVndlFXZEZRVTFDTUVkQk1WVmtSR2RSVjBKQ1VUbEtZWFpGVEVGVk9VMUZSMHBDVjJ4UVdtbzJSM041V2pWM1ZFRm1RbWRPVmtoVFRVVkhSRUZYWjBKU1kxYzFRelJFYmpaQ05UWXphbTVWTW01RFZIRlVXWEIxWmt0RVFqQkNaMDVXU0ZJNFJXSlVRbkpOUjIxbldqWkNiR2h0VG05a1NGSjNZM3B2ZGt3eVduQmFSemxvWWtkNGNGbFhOV3BhVXpWcVluazFkV1ZwT1hwWlYxcHNaRWhzZFZwWVVuZGhNbXQyV1ROS2Mwd3dXa3BTUlRoc1RXcENSMWxYZEd4S1ZFbDNWVzA1ZG1SRFZYbE5SVTVzWTI1U2NGcHRiR3BaV0ZKc1NsUkpkMUZZVmpCaFJ6bDVZVmhTTlVwVVNYZE5ha0Y0VDBNMWFtTnRkM2RsZDFsSlMzZFpRa0pSVlVoQlVVVkZZbnBDZEUxSGMwZERRM05IUVZGVlJrSjZRVUpvYkRsdlpFaFNkMk42YjNaTU1scHdXa2M1YUdKSGVIQlpWelZxV2xNMWFtSjVOWFZsYVRsNldWZGFiR1JJYkhWYVdGSjNZVEpyZGxKcmJFVlVlVlY1VFVWYWFHRXlWV3hOYWtKVFlqSTVNRXBVU1hkUk1sWjVaRWRzYldGWFRtaGtSMVZzVFdwQ1FtUllVbTlpTTBwd1pFaHJiRTFxUVhsTlJFVTBURzFPZVdSRVFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGWlZVRmxhbTl4VFhwbFNsWkhhR2RXUTB0NE1Fd3ZTbmhhY2xnNWIxRkZiMnN3TVdReFkwTlJNRFZuWkdObGEyUjVRelp2Ykd4cllrRklUMGR0Y21WRGRuZEhiMVJJTWpkS05XdG5iSEpHYTFRd1pVWndSMjFDTTBGTWNHaDZPVmhPWm1oaWF6a3JSVk5YWm5adk1VODNiSEJVZGxNeU9YRkhRU3RQTUVweFFUaERkek50TDFoSlIxVllabTA0YjJkU1FTdDBaRTB6TW14S1RtcDBVR1Y1Y1Vad1RscHdjRWRrYWxRNGRqQnZSamhaZDBWc2VYRkJZMUl4VjBveldYUXdZeXRyWmxwQk5teEhTR3RZTkVjMGFYVnNjMUJIYlV4elUwNHJZMXBEVG5GR2IwTklNMmRYWlhwSWRucHNkWEJQUm1abU5tdEdVMU5CVVZKelJXcHZTeXR6UTJGS1JHeFJOM1pIUVU5R1pGZFlVR1ZhWnpWT00yRlpTM1ZoSzFCSVN6WlJWVVoyTVU4emMxcGpjbFJSVkZwbk5EZHdVRVpYY1daeVNXVTBiWFpyV2pObmFGUm9OSEZRUmtKaVlsZGhMMUZPYUdjOVBTSmRmUS5leUp1YjI1alpTSTZJbFpNVXpsa01FZFBaelJDUTIxV2JrUkpkVEJ3TjBSbUx6WjRVbUp1ZEZwUU5VazNSRzVtTTJ4SmFFVTlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFOalV6TWpnd09Ua3hNek1zSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtRnVaSEp2YVdRdWEyVjVjM1J2Y21VdVlXNWtjbTlwWkd0bGVYTjBiM0psWkdWdGJ5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbVJOTDB4VlNGTkpPVk5yVVdoYVNFaHdVVmRTYm5wS00wMTJka0l5UVU1VFlYVnhXVUZCWWxNeVNtYzlJaXdpWVhCclEyVnlkR2xtYVdOaGRHVkVhV2RsYzNSVGFHRXlOVFlpT2xzaVluTmlOQzlYVVdSaFlVOVhXVU5rTDJvNVQwcHBVWEJuTjJJd2FYZEdaMEZqTDNwNlFURjBRMlozUlQwaVhTd2lZM1J6VUhKdlptbHNaVTFoZEdOb0lqcDBjblZsTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC5ScjV3SjdjeExUZmRZOTZDdkdHbC1Uc3ZjUGJfWG0tSUZnd2hTZmdzY1YxczI1XzRyMUh1WnB4M1IxOGhwdU5wTkl3ZWdGRkJIVUM5LXVzNUhHQjdZbnZKbmNZblNTWmk1TUVjQXNIMTlSNXdZRWlzR2ViTmNHZGh6TG1WZmtMdHF4dkZ6VWlXUkYtZkZuOEJsVExRR3UwdXJ1VFltZXEyWHlXTUdrVWVFX3R3V0dkTGMya0xNTlRLWTI5ckxjLTZmS2t1QlpNT0xucC1hQ3I5aHlKWFVKQ18tWjB2SUVtalZJeDk2N3UwTlRiUjFrRlVtemxxeU5FV2hzZW1vX0Rhd1N0WEdFdVdqSS1MVWl2a3dLOVh2TUlwc2cyV0lxRUZSZXBuY09Pc0dpNkUwZk81aVlSRjdpWE4tZTJfWEM0dXU3eEpXcm1KdmhsTTNjVVRLVW9xWUFoYXV0aERhdGFZAWeWBOqCgk6YpK2hS0Ri0Nc6jsRpEw2pGxkwdFkin3SjWUEAAABuyHzdl1bBSbieJMs2NlTzUAAgDMKtmWAP8EW2CBOpmmamxO4ON8yNt5q2udPoNzPdKICkAQMDOQEAIFkBAOR_FviYQDU2FOGGcCI_3nyN1Jb7pY2KFPl1pFbvZyRMhLp8ctnZzRZ2bKyZwHGuelF2gU4k_uMZOajCYR3kb8piARyotK2KD1wEZstssdPCz9Us-ojdQC0YKbFgk6aIhXPy598OtH8io57YW2EuurbduZeacuH9jW3WciuFVa1J8UHNXrdZRui2I_sxL9vmifQWhzWEWfio-kvcGJ6nI3QPrOdb_eOZTfKw17dwjwpf7mynsH95Knkc67jiF_MJT1GzSSMO2S3S_EnyBw1EJsyg8lYH2g4mG3djA648DWMpE1B4h4i00W_R6ZIzUDulXLKVz33OyBhHINcTCic6lOUhQwEAAQ","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLnNwb21reS1sYWJzLmNvbSIsImNoYWxsZW5nZSI6IkJBSzhrb3hYbEZUMDdQanBXMnJCaGRnMGlPNVNzV0lQVURweHd0N1JrRlkiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},"type":"public-key"}';

        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
        $publicKeyCredential = self::$kernel->getContainer()->get(PublicKeyCredentialLoader::class)->load($result);

        $descriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        static::assertEquals(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->getType());
        static::assertEquals(hex2bin('0cc2ad99600ff045b60813a99a66a6c4ee0e37cc8db79ab6b9d3e83733dd2880'), $descriptor->getId());
        static::assertEquals([], $descriptor->getTransports());

        $response = $publicKeyCredential->getResponse();
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        static::assertEquals(AttestationStatement::TYPE_BASIC, $response->getAttestationObject()->getAttStmt()->getType());
        static::assertInstanceOf(CertificateTrustPath::class, $response->getAttestationObject()->getAttStmt()->getTrustPath());

        $uri = $this->prophesize(UriInterface::class);
        $uri->getHost()->willReturn('webauthn.spomky-labs.com');
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getUri()->willReturn($uri->reveal());

        self::$kernel->getContainer()->get(AuthenticatorAttestationResponseValidator::class)->check(
            $publicKeyCredential->getResponse(),
            $publicKeyCredentialCreationOptions,
            $request->reveal()
        );
    }

    /**
     * @test
     */
    public function aPublicKeyCredentialCreationOptionsCanBeCreatedFromProfile(): void
    {
        self::bootKernel();

        /** @var PublicKeyCredentialCreationOptionsFactory $factory */
        $factory = self::$kernel->getContainer()->get(PublicKeyCredentialCreationOptionsFactory::class);
        $options = $factory->create(
            'default',
            new PublicKeyCredentialUserEntity('test@foo.com', random_bytes(64), 'Test PublicKeyCredentialUserEntity')
        );

        static::assertEquals(32, mb_strlen($options->getChallenge(), '8bit'));
        static::assertInstanceOf(AuthenticationExtensionsClientInputs::class, $options->getExtensions());
        static::assertEquals([], $options->getExcludeCredentials());
        static::assertEquals(11, \count($options->getPubKeyCredParams()));
        static::assertEquals('none', $options->getAttestation());
        static::assertEquals(60000, $options->getTimeout());
        static::assertInstanceOf(PublicKeyCredentialRpEntity::class, $options->getRp());
        static::assertInstanceOf(PublicKeyCredentialUserEntity::class, $options->getUser());
        static::assertInstanceOf(AuthenticatorSelectionCriteria::class, $options->getAuthenticatorSelection());
    }
}
