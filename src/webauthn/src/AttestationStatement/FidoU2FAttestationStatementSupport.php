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

namespace Webauthn\AttestationStatement;

use Assert\Assertion;
use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\StringStream;
use InvalidArgumentException;
use function Safe\openssl_pkey_get_public;
use function Safe\sprintf;
use Throwable;
use Webauthn\AuthenticatorData;
use Webauthn\CertificateToolbox;
use Webauthn\TrustPath\CertificateTrustPath;

final class FidoU2FAttestationStatementSupport implements AttestationStatementSupport
{
    /**
     * @var Decoder
     */
    private $decoder;

    public function __construct(Decoder $decoder)
    {
        $this->decoder = $decoder;
    }

    public function name(): string
    {
        return 'fido-u2f';
    }

    public function load(array $attestation): AttestationStatement
    {
        Assertion::keyExists($attestation, 'attStmt', 'Invalid attestation object');
        foreach (['sig', 'x5c'] as $key) {
            Assertion::keyExists($attestation['attStmt'], $key, sprintf('The attestation statement value "%s" is missing.', $key));
        }
        $certificates = $attestation['attStmt']['x5c'];
        Assertion::isArray($certificates, 'The attestation statement value "x5c" must be a list with one certificate.');
        Assertion::count($certificates, 1, 'The attestation statement value "x5c" must be a list with one certificate.');
        Assertion::allString($certificates, 'The attestation statement value "x5c" must be a list with one certificate.');

        reset($certificates);
        $certificates = CertificateToolbox::convertAllDERToPEM($certificates);
        $this->checkCertificate($certificates[0]);

        return AttestationStatement::createBasic($attestation['fmt'], $attestation['attStmt'], new CertificateTrustPath($certificates));
    }

    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        $trustPath = $attestationStatement->getTrustPath();
        Assertion::isInstanceOf($trustPath, CertificateTrustPath::class, 'Invalid trust path');
        $dataToVerify = "\0";
        $dataToVerify .= $authenticatorData->getRpIdHash();
        $dataToVerify .= $clientDataJSONHash;
        $dataToVerify .= $authenticatorData->getAttestedCredentialData()->getCredentialId();
        $dataToVerify .= $this->extractPublicKey($authenticatorData->getAttestedCredentialData()->getCredentialPublicKey());

        return 1 === openssl_verify($dataToVerify, $attestationStatement->get('sig'), $trustPath->getCertificates()[0], OPENSSL_ALGO_SHA256);
    }

    private function extractPublicKey(?string $publicKey): string
    {
        Assertion::notNull($publicKey, 'The attested credential data does not contain a valid public key.');

        $publicKey = $this->decoder->decode(new StringStream($publicKey));
        Assertion::isInstanceOf($publicKey, MapObject::class, 'The attested credential data does not contain a valid public key.');

        $publicKey = $publicKey->getNormalizedData();
        Assertion::false(!\array_key_exists(-2, $publicKey) || !\is_string($publicKey[-2]) || 32 !== mb_strlen($publicKey[-2], '8bit'), 'The public key of the attestation statement is not valid.');
        Assertion::false(!\array_key_exists(-3, $publicKey) || !\is_string($publicKey[-3]) || 32 !== mb_strlen($publicKey[-3], '8bit'), 'The public key of the attestation statement is not valid.');

        return "\x04".$publicKey[-2].$publicKey[-3];
    }

    private function checkCertificate(string $publicKey): void
    {
        try {
            $resource = openssl_pkey_get_public($publicKey);
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('The certificate in the attestation statement is not valid.', 0, $throwable);
        }
        $details = openssl_pkey_get_details($resource);
        Assertion::keyExists($details, 'ec', 'The certificate in the attestation statement is not valid.');
        Assertion::keyExists($details['ec'], 'curve_name', 'The certificate in the attestation statement is not valid.');
        Assertion::eq($details['ec']['curve_name'], 'prime256v1', 'The certificate in the attestation statement is not valid.');
        Assertion::keyExists($details['ec'], 'curve_oid', 'The certificate in the attestation statement is not valid.');
        Assertion::eq($details['ec']['curve_oid'], '1.2.840.10045.3.1.7', 'The certificate in the attestation statement is not valid.');
    }
}
