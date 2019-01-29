<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\AttestationStatement;

use Assert\Assertion;
use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\StringStream;
use Cose\Algorithm\Mac\Mac;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\Signature;
use Cose\Algorithms;
use Cose\Key\Key;
use Webauthn\AuthenticatorData;
use Webauthn\CertificateToolbox;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EcdaaKeyIdTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

final class PackedAttestationStatementSupport implements AttestationStatementSupport
{
    /**
     * @var Decoder
     */
    private $decoder;

    /**
     * @var Manager
     */
    private $algorithmManager;

    public function __construct(Decoder $decoder, Manager $algorithmManager)
    {
        $this->decoder = $decoder;
        $this->algorithmManager = $algorithmManager;
    }

    public function name(): string
    {
        return 'packed';
    }

    public function load(array $attestation): AttestationStatement
    {
        Assertion::keyExists($attestation['attStmt'], 'sig', 'The attestation statement value "sig" is missing.');
        Assertion::keyExists($attestation['attStmt'], 'alg', 'The attestation statement value "alg" is missing.');
        Assertion::string($attestation['attStmt']['sig'], 'The attestation statement value "sig" is missing.');
        switch (true) {
            case key_exists('x5c', $attestation['attStmt']):
                return $this->loadBasicType($attestation);
            case key_exists('ecdaaKeyId', $attestation['attStmt']):
                return $this->loadEcdaaType($attestation['attStmt']);
            default:
                return $this->loadEmptyType($attestation);
        }
    }

    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        switch (true) {
            case $attestationStatement->getTrustPath() instanceof CertificateTrustPath:
                return $this->processWithCertificate($clientDataJSONHash, $attestationStatement, $authenticatorData);
            case $attestationStatement->getTrustPath() instanceof EcdaaKeyIdTrustPath:
                return $this->processWithECDAA($clientDataJSONHash, $attestationStatement, $authenticatorData);
            case $attestationStatement->getTrustPath() instanceof EmptyTrustPath:
                return $this->processWithSelfAttestation($clientDataJSONHash, $attestationStatement, $authenticatorData);
            default:
                throw new \InvalidArgumentException('Unsupported attestation statement');
        }
    }

    private function loadBasicType(array $attestation): AttestationStatement
    {
        $certificates = $attestation['attStmt']['x5c'];
        Assertion::isArray($certificates, 'The attestation statement value "x5c" must be a list with at least one certificate.');

        //Check certificate CA chain and returns the Attestation Certificate
        $certificates = CertificateToolbox::convertAllDERToPEM($certificates);
        CertificateToolbox::checkChain($certificates);

        return AttestationStatement::createBasic($attestation['fmt'], $attestation['attStmt'], new CertificateTrustPath($certificates));
    }

    private function loadEcdaaType(array $attestation): AttestationStatement
    {
        $ecdaaKeyId = $attestation['attStmt']['ecdaaKeyId'];
        Assertion::string($ecdaaKeyId, 'The attestation statement value "ecdaaKeyId" is invalid.');

        return AttestationStatement::createEcdaa($attestation['fmt'], $attestation['attStmt'], new EcdaaKeyIdTrustPath($attestation['ecdaaKeyId']));
    }

    private function loadEmptyType(array $attestation): AttestationStatement
    {
        return AttestationStatement::createSelf($attestation['fmt'], $attestation['attStmt'], new EmptyTrustPath());
    }

    private function checkCertificate(string $attestnCert, AuthenticatorData $authenticatorData): void
    {
        $parsed = openssl_x509_parse($attestnCert);

        //Check version
        Assertion::false(!isset($parsed['version']) || 2 !== $parsed['version'], 'Invalid certificate version');

        //Check subject field
        Assertion::false(!isset($parsed['name']) || false === mb_strpos($parsed['name'], '/OU=Authenticator Attestation'), 'Invalid certificate name. The Subject Organization Unit must be "Authenticator Attestation"');

        //Check extensions
        Assertion::false(!isset($parsed['extensions']) || !\is_array($parsed['extensions']), 'Certificate extensions are missing');

        //Check certificate is not a CA cert
        Assertion::false(!isset($parsed['extensions']['basicConstraints']) || 'CA:FALSE' !== $parsed['extensions']['basicConstraints'], 'The Basic Constraints extension must have the CA component set to false');

        // id-fido-gen-ce-aaguid OID check
        Assertion::false(\in_array('1.3.6.1.4.1.45724.1.1.4', $parsed['extensions'], true) && !hash_equals($authenticatorData->getAttestedCredentialData()->getAaguid(), $parsed['extensions']['1.3.6.1.4.1.45724.1.1.4']), 'The value of the "aaguid" does not match with the certificate');
    }

    private function processWithCertificate(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        $certificates = $attestationStatement->getTrustPath()->getCertificates();
        Assertion::isArray($certificates, 'The attestation statement value "x5c" must be a list with at least one certificate.');

        // Check certificate CA chain and returns the Attestation Certificate
        $this->checkCertificate($certificates[0], $authenticatorData);

        // Get the COSE algorithm identifier and the corresponding OpenSSL one
        $coseAlgorithmIdentifier = \intval($attestationStatement->get('alg'));
        $opensslAlgorithmIdentifier = Algorithms::getOpensslAlgorithmFor($coseAlgorithmIdentifier);

        // Verification of the signature
        $signedData = $authenticatorData->getAuthData().$clientDataJSONHash;
        $result = openssl_verify($signedData, $attestationStatement->get('sig'), $certificates[0], $opensslAlgorithmIdentifier);

        return 1 === $result;
    }

    private function processWithECDAA(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        throw new \RuntimeException('ECDAA not supported');
    }

    private function processWithSelfAttestation(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        $publicKey = $this->decoder->decode(new StringStream($authenticatorData->getAttestedCredentialData()->getCredentialPublicKey()));
        Assertion::isInstanceOf($publicKey, MapObject::class, 'The attestated credential data does not contain a valid public key.');
        $publicKey = $publicKey->getNormalizedData();
        Assertion::isArray($publicKey, 'The attestated credential data does not contain a valid public key.');
        $publicKey = new Key($publicKey);
        Assertion::eq($publicKey->alg(), \intval($attestationStatement->get('alg')), 'The algorithm of the attestation statement and the key are not identical.');

        $dataToVerify = $authenticatorData->getAuthData().$clientDataJSONHash;

        $algorithm = $this->algorithmManager->get(\intval($attestationStatement->get('alg')));
        switch (true) {
            case $algorithm instanceof Signature:
            case $algorithm instanceof Mac:
                return $algorithm->verify($dataToVerify, $publicKey, $attestationStatement->get('sig'));
            default:
                throw new \RuntimeException('Invalid algorithm');
        }
    }
}
