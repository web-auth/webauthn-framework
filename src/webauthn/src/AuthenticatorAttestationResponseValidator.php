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

namespace Webauthn;

use Assert\Assertion;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\MetadataService\MetadataStatement;
use Webauthn\TokenBinding\TokenBindingHandler;
use Webauthn\TrustPath\CertificateTrustPath;

class AuthenticatorAttestationResponseValidator
{
    /**
     * @var AttestationStatementSupportManager
     */
    private $attestationStatementSupportManager;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $publicKeyCredentialSource;

    /**
     * @var TokenBindingHandler
     */
    private $tokenBindingHandler;

    /**
     * @var ExtensionOutputCheckerHandler
     */
    private $extensionOutputCheckerHandler;

    public function __construct(AttestationStatementSupportManager $attestationStatementSupportManager, PublicKeyCredentialSourceRepository $publicKeyCredentialSource, TokenBindingHandler $tokenBindingHandler, ExtensionOutputCheckerHandler $extensionOutputCheckerHandler)
    {
        $this->attestationStatementSupportManager = $attestationStatementSupportManager;
        $this->publicKeyCredentialSource = $publicKeyCredentialSource;
        $this->tokenBindingHandler = $tokenBindingHandler;
        $this->extensionOutputCheckerHandler = $extensionOutputCheckerHandler;
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#registering-a-new-credential
     */
    public function check(AuthenticatorAttestationResponse $authenticatorAttestationResponse, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, ServerRequestInterface $request): PublicKeyCredentialSource
    {
        /** @see 7.1.1 */
        //Nothing to do

        /** @see 7.1.2 */
        $C = $authenticatorAttestationResponse->getClientDataJSON();

        /* @see 7.1.3 */
        Assertion::eq('webauthn.create', $C->getType(), 'The client data type is not "webauthn.create".');

        /* @see 7.1.4 */
        Assertion::true(hash_equals($publicKeyCredentialCreationOptions->getChallenge(), $C->getChallenge()), 'Invalid challenge.');

        /** @see 7.1.5 */
        $rpId = $publicKeyCredentialCreationOptions->getRp()->getId() ?? $request->getUri()->getHost();

        $parsedRelyingPartyId = parse_url($C->getOrigin());
        Assertion::isArray($parsedRelyingPartyId, sprintf('The origin URI "%s" is not valid', $C->getOrigin()));
        Assertion::keyExists($parsedRelyingPartyId, 'scheme', 'Invalid origin rpId.');
        $scheme = $parsedRelyingPartyId['scheme'] ?? '';
        Assertion::eq('https', $scheme, 'Invalid scheme. HTTPS required.');
        $clientDataRpId = $parsedRelyingPartyId['host'] ?? '';
        Assertion::notEmpty($clientDataRpId, 'Invalid origin rpId.');
        $rpIdLength = mb_strlen($rpId);
        Assertion::eq(mb_substr($clientDataRpId, -$rpIdLength), $rpId, 'rpId mismatch.');

        /* @see 7.1.6 */
        if (null !== $C->getTokenBinding()) {
            $this->tokenBindingHandler->check($C->getTokenBinding(), $request);
        }

        /** @see 7.1.7 */
        $clientDataJSONHash = hash('sha256', $authenticatorAttestationResponse->getClientDataJSON()->getRawData(), true);

        /** @see 7.1.8 */
        $attestationObject = $authenticatorAttestationResponse->getAttestationObject();

        /** @see 7.1.9 */
        $rpIdHash = hash('sha256', $rpId, true);
        Assertion::true(hash_equals($rpIdHash, $attestationObject->getAuthData()->getRpIdHash()), 'rpId hash mismatch.');

        /* @see 7.1.10 */
        /* @see 7.1.11 */
        if (AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED === $publicKeyCredentialCreationOptions->getAuthenticatorSelection()->getUserVerification()) {
            Assertion::true($attestationObject->getAuthData()->isUserPresent(), 'User was not present');
            Assertion::true($attestationObject->getAuthData()->isUserVerified(), 'User authentication required.');
        }

        /* @see 7.1.12 */
        $extensions = $attestationObject->getAuthData()->getExtensions();
        if (null !== $extensions) {
            $this->extensionOutputCheckerHandler->check($extensions);
        }

        /** @see 7.1.13 */
        $fmt = $attestationObject->getAttStmt()->getFmt();
        Assertion::true($this->attestationStatementSupportManager->has($fmt), 'Unsupported attestation statement format.');

        /** @see 7.1.14 */
        $attestationStatementSupport = $this->attestationStatementSupportManager->get($fmt);
        $this->checkMetadataStatement($attestationObject);
        Assertion::true($attestationStatementSupport->isValid($clientDataJSONHash, $attestationObject->getAttStmt(), $attestationObject->getAuthData()), 'Invalid attestation statement.');

        /* @see 7.1.15 */
        /* @see 7.1.16 */
        /* @see 7.1.17 */
        Assertion::true($attestationObject->getAuthData()->hasAttestedCredentialData(), 'There is no attested credential data.');
        $attestedCredentialData = $attestationObject->getAuthData()->getAttestedCredentialData();
        Assertion::notNull($attestedCredentialData, 'There is no attested credential data.');
        $credentialId = $attestedCredentialData->getCredentialId();
        Assertion::null($this->publicKeyCredentialSource->findOneByCredentialId($credentialId), 'The credential ID already exists.');

        /* @see 7.1.18 */
        /* @see 7.1.19 */
        return $this->createPublicKeyCredentialSource(
            $credentialId,
            $attestedCredentialData,
            $attestationObject,
            $publicKeyCredentialCreationOptions->getUser()->getId()
        );
    }

    private function checkCertificateChain(AttestationStatement $attestationStatement, ?MetadataStatement $metadataStatement): void
    {
        $trustPath = $attestationStatement->getTrustPath();
        if (!$trustPath instanceof CertificateTrustPath) {
            return;
        }
        $authenticatorCertificates = $trustPath->getCertificates();

        if (null === $metadataStatement) {
            CertificateToolbox::checkChain($authenticatorCertificates);

            return;
        }

        $metadataStatementCertificates = $metadataStatement->getAttestationRootCertificates();
        foreach ($metadataStatementCertificates as $key => $attestationRootCertificate) {
            $metadataStatementCertificates[$key] = CertificateToolbox::fixPEMStructure($attestationRootCertificate);
        }
        CertificateToolbox::checkChain($authenticatorCertificates, $metadataStatementCertificates);
    }

    private function checkMetadataStatement(AttestationObject $attestationObject): void
    {
        $attestationStatement = $attestationObject->getAttStmt();
        $metadataStatement = $attestationObject->getMetadataStatement();

        //If the MDS verification is enforced and an Attestation Statement is present, we must check the MDS is present.
        // Null AAGUID (=00000000-0000-0000-0000-000000000000) are not concerned
        if (null === $metadataStatement && AttestationStatement::TYPE_NONE !== $attestationStatement->getType() && '00000000-0000-0000-0000-000000000000' !== $attestationObject->getAuthData()->getAttestedCredentialData()->getAaguid()->toString()) {
            throw new RuntimeException(sprintf('An attestation statement has been asked but the metadata statement is missing'));
        }
        $this->checkCertificateChain($attestationStatement, $metadataStatement);
        if (null === $metadataStatement) {
            return;
        }

        // Check Attestation Type is allowed
        if (0 !== \count($metadataStatement->getAttestationTypes())) {
            $type = $this->getAttestationType($attestationStatement);
            Assertion::inArray($type, $metadataStatement->getAttestationTypes(), 'Invalid attestation statement. The attestation type is not allowed for this authenticator');
        }

        //FIXME: to decide later if relevant
        /*Assertion::eq('fido2', $metadataStatement->getProtocolFamily(), sprintf('The protocol family of the authenticator "%s" should be "fido2". Got "%s".', $aaguid, $metadataStatement->getProtocolFamily()));
        if (null !== $metadataStatement->getAssertionScheme()) {
            Assertion::eq('FIDOV2', $metadataStatement->getAssertionScheme(), sprintf('The assertion scheme of the authenticator "%s" should be "FIDOV2". Got "%s".', $aaguid, $metadataStatement->getAssertionScheme()));
        }*/
    }

    private function createPublicKeyCredentialSource(string $credentialId, AttestedCredentialData $attestedCredentialData, AttestationObject $attestationObject, string $userHandle): PublicKeyCredentialSource
    {
        return new PublicKeyCredentialSource(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            $attestationObject->getAttStmt()->getType(),
            $attestationObject->getAttStmt()->getTrustPath(),
            $attestedCredentialData->getAaguid(),
            $attestedCredentialData->getCredentialPublicKey(),
            $userHandle,
            $attestationObject->getAuthData()->getSignCount()
        );
    }

    private function getAttestationType(AttestationStatement $attestationStatement): int
    {
        switch ($attestationStatement->getType()) {
            case AttestationStatement::TYPE_BASIC:
                return MetadataStatement::ATTESTATION_BASIC_FULL;
            case AttestationStatement::TYPE_SELF:
                return MetadataStatement::ATTESTATION_BASIC_SURROGATE;
            case AttestationStatement::TYPE_ATTCA:
                return MetadataStatement::ATTESTATION_ATTCA;
            case AttestationStatement::TYPE_ECDAA:
                return MetadataStatement::ATTESTATION_ECDAA;
            default:
                throw new InvalidArgumentException('Invalid attestation type');
        }
    }
}
