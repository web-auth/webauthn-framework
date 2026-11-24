<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Firewall;

use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\Tests\Bundle\Functional\AttestationDirectAppKernel;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;
use Webauthn\Tests\Functional\SoftwareAuthenticator;

/**
 * GHSA-473f-pfcw-p4h2, through the firewall registration: the creation profile requests direct attestation, the
 * metadata service is enabled and the default client override policy applies. A software authenticator claims the
 * AAGUID of a model listed in the metadata ("Security Key by Yubico") and signs a packed statement with an
 * attestation certificate it made itself.
 *
 * Whatever conveyance the options request asks for, the statement is verified against the metadata and refused: a
 * client that asks for "none" gets the conveyance of the profile, and one that asks for "indirect" gets it but is
 * verified all the same. Before 5.3.13, asking for "none" stored the forged statement as a basic attestation of the
 * claimed model.
 *
 * @see https://github.com/web-auth/webauthn-framework/security/advisories/GHSA-473f-pfcw-p4h2
 * @internal
 */
final class AttestationConveyanceOverrideTest extends WebauthnTestCase
{
    /**
     * The AAGUID of tests/metadataStatements/yubikey.json.
     */
    private const SECURITY_KEY_BY_YUBICO = 'f8a011f3-8c0a-4d15-8006-17111f9edc7d';

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function optionsRequests(): iterable
    {
        yield 'no attestation member' => [[], PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT];
        yield 'the client asks for none' => [
            [
                'attestation' => PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            ],
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        ];
        yield 'the client asks for indirect' => [
            [
                'attestation' => PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
            ],
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
        ];
    }

    /**
     * @param array<string, string> $optionsRequestMembers
     */
    #[Test]
    #[DataProvider('optionsRequests')]
    public function aSelfMadeAttestationOfAKnownModelIsRefused(
        array $optionsRequestMembers,
        string $expectedConveyance
    ): void {
        $browser = static::createClient([], [
            'HTTPS' => 'on',
            'HTTP_HOST' => 'localhost',
        ]);
        $username = 'visitor-' . bin2hex(random_bytes(8));

        $options = $this->postJson($browser, '/api/register/options', json_encode(array_merge([
            'username' => $username,
            'displayName' => $username,
        ], $optionsRequestMembers), JSON_THROW_ON_ERROR));
        static::assertSame($expectedConveyance, $options['attestation']);

        $publicKeyCredential = SoftwareAuthenticator::packed(
            Base64UrlSafe::decodeNoPadding($options['challenge']),
            self::SECURITY_KEY_BY_YUBICO
        );
        $result = $this->postJson($browser, '/api/register', $publicKeyCredential);
        static::assertSame('error', $result['status']);
        static::assertSame('Unable to validate the certificate chain.', $result['errorMessage']);

        $credentialId = json_decode($publicKeyCredential, true, 512, JSON_THROW_ON_ERROR)['rawId'];
        static::assertNull(
            static::getContainer()
                ->get(PublicKeyCredentialSourceRepository::class)
                ->findOneByCredentialId(Base64UrlSafe::decodeNoPadding($credentialId))
        );
    }

    protected static function getKernelClass(): string
    {
        return AttestationDirectAppKernel::class;
    }

    /**
     * @return array<string, mixed>
     */
    private function postJson(KernelBrowser $browser, string $path, string $body): array
    {
        $browser->request(Request::METHOD_POST, $path, [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], $body);

        return json_decode((string) $browser->getResponse()->getContent(), true, 512, JSON_THROW_ON_ERROR);
    }
}
