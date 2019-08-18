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

namespace Webauthn\Tests\Unit\AttestationStatement;

use Base64Url\Base64Url;
use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\SignedIntegerObject;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Uuid;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorData;
use Webauthn\CertificateToolbox;
use Webauthn\MetadataService\SimpleMetadataStatementRepository;
use Webauthn\TrustPath\CertificateTrustPath;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport
 */
class FidoU2FAttestationStatementSupportTest extends TestCase
{
    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainTheRequiredSignature(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The attestation statement value "sig" is missing.');
        $support = new FidoU2FAttestationStatementSupport(null, new SimpleMetadataStatementRepository(new FilesystemAdapter('webauthn')));

        static::assertEquals('fido-u2f', $support->name());
        static::assertFalse($support->load([
            'fmt' => 'fido-u2f',
            'attStmt' => [],
        ]));
    }

    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainTheRequiredCertificateList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The attestation statement value "x5c" is missing.');
        $support = new FidoU2FAttestationStatementSupport(null, new SimpleMetadataStatementRepository(new FilesystemAdapter('webauthn')));
        static::assertFalse($support->load([
            'fmt' => 'fido-u2f',
            'attStmt' => [
                'sig' => 'foo-bar',
            ],
        ]));
    }

    /**
     * @test
     */
    public function theAttestationStatementContainsAnEmptyCertificateList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The attestation statement value "x5c" must be a list with one certificate.');
        $support = new FidoU2FAttestationStatementSupport(null, new SimpleMetadataStatementRepository(new FilesystemAdapter('webauthn')));

        static::assertEquals('fido-u2f', $support->name());
        static::assertFalse($support->load([
            'fmt' => 'fido-u2f',
            'attStmt' => [
                'sig' => 'foo-bar',
                'x5c' => [],
            ],
        ]));
    }

    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainAValidCertificateList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid certificate or certificate chain');
        $support = new FidoU2FAttestationStatementSupport(null, new SimpleMetadataStatementRepository(new FilesystemAdapter('webauthn')));

        static::assertEquals('fido-u2f', $support->name());
        static::assertFalse($support->load([
            'fmt' => 'fido-u2f',
            'attStmt' => [
                'sig' => 'foo-bar',
                'x5c' => ['FOO'],
            ],
        ]));
    }

    /**
     * @test
     */
    public function theAttestationStatementContain(): void
    {
        $support = new FidoU2FAttestationStatementSupport(null, new SimpleMetadataStatementRepository(new FilesystemAdapter('webauthn')));

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getAttStmt()->willReturn([
            'sig' => 'FOO',
            'x5c' => [
                Base64Url::decode('Ws1pyRaocwNNxYIXIHttjOO1628kVQ2EK6EVVZ_wWKs089-rszT2fkSnSfm4V6wV9ryz2-K8Vm5Fs_r7ctAcoQ'),
            ],
        ]);
        $attestationStatement->has('sig')->willReturn(true);
        $attestationStatement->get('sig')->willReturn(random_bytes(70));
        $attestationStatement->has('x5c')->willReturn(true);
        $attestationStatement->get('x5c')->willReturn([base64_decode('MIICLTCCARegAwIBAgIEBbYFeTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCgxJjAkBgNVBAMMHVl1YmljbyBVMkYgRUUgU2VyaWFsIDk1ODE1MDMzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/bjes6HtcOtjbAZutgBplqX5cPy124j8OzBdQeWWbwwbVLhS/vCgkH7Rfzv/wp1NMhuc+KhKLOqgOMq9NdWY3qMmMCQwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwCwYJKoZIhvcNAQELA4IBAQB+0/tszCUgE/gvIYwqN9pgMdIOfzCB2vyusSj8f5sjORS/tk1hNfF84iH6dk9FPvEnOozpZZVkQrsvHkdIP3N9y8mLWFN3/vULJw4CifiENvGtz0myYh7l4wLfVVuat0Jy4Gn5GBSbPexPEiKLEMD4jeNq9Yp0u0Qrha4AU2S9pnAgWPwfLYebUwER6mDobGPxf6WUTMg/CqJphIs+44imwJ5rBZU/y7j0foOifgBypjwyrWSGTpJtcRL6GZf3g5ZW+7Mr6PeInQ8BRVGaJ6/djkawTKQpDYVAtjS4hhYedYjIYpnc3WQ10WeKOm8KdIKcTdP3DDUk0d3xbXit0htk', true)]);
        $attestationStatement->getTrustPath()->willReturn(new CertificateTrustPath([CertificateToolbox::convertDERToPEM(base64_decode('MIICLTCCARegAwIBAgIEBbYFeTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCgxJjAkBgNVBAMMHVl1YmljbyBVMkYgRUUgU2VyaWFsIDk1ODE1MDMzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/bjes6HtcOtjbAZutgBplqX5cPy124j8OzBdQeWWbwwbVLhS/vCgkH7Rfzv/wp1NMhuc+KhKLOqgOMq9NdWY3qMmMCQwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwCwYJKoZIhvcNAQELA4IBAQB+0/tszCUgE/gvIYwqN9pgMdIOfzCB2vyusSj8f5sjORS/tk1hNfF84iH6dk9FPvEnOozpZZVkQrsvHkdIP3N9y8mLWFN3/vULJw4CifiENvGtz0myYh7l4wLfVVuat0Jy4Gn5GBSbPexPEiKLEMD4jeNq9Yp0u0Qrha4AU2S9pnAgWPwfLYebUwER6mDobGPxf6WUTMg/CqJphIs+44imwJ5rBZU/y7j0foOifgBypjwyrWSGTpJtcRL6GZf3g5ZW+7Mr6PeInQ8BRVGaJ6/djkawTKQpDYVAtjS4hhYedYjIYpnc3WQ10WeKOm8KdIKcTdP3DDUk0d3xbXit0htk', true))]));

        $attestedCredentialData = $this->prophesize(AttestedCredentialData::class);
        $attestedCredentialData->getAaguid()->willReturn(Uuid::fromString('00000000-0000-0000-0000-000000000000'));
        $attestedCredentialData->getCredentialId()->willReturn('CREDENTIAL_ID');
        $attestedCredentialData->getCredentialPublicKey()->willReturn(
            new MapObject([
                new MapItem(SignedIntegerObject::createFromGmpValue(gmp_init(-2)), new ByteStringObject(hex2bin('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'))),
                new MapItem(SignedIntegerObject::createFromGmpValue(gmp_init(-3)), new ByteStringObject(hex2bin('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'))),
            ])
        );

        $authenticatorData = $this->prophesize(AuthenticatorData::class);
        $authenticatorData->getRpIdHash()->willReturn('FOO');
        $authenticatorData->getAttestedCredentialData()->willReturn($attestedCredentialData->reveal());

        static::assertEquals('fido-u2f', $support->name());
        static::assertFalse($support->isValid('FOO', $attestationStatement->reveal(), $authenticatorData->reveal()));
    }
}
