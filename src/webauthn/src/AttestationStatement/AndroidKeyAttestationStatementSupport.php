<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use function array_key_exists;
use CBOR\Decoder;
use CBOR\Normalizable;
use Cose\Algorithms;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\RsaKey;
use function count;
use FG\ASN1\ASNObject;
use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use function hex2bin;
use function is_array;
use function openssl_pkey_get_public;
use function openssl_verify;
use Psr\EventDispatcher\EventDispatcherInterface;
use Webauthn\AuthenticatorData;
use Webauthn\Event\AttestationStatementLoaded;
use Webauthn\Exception\AttestationStatementLoadingException;
use Webauthn\Exception\AttestationStatementVerificationException;
use Webauthn\Exception\InvalidAttestationStatementException;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\Event\NullEventDispatcher;
use Webauthn\StringStream;
use Webauthn\TrustPath\CertificateTrustPath;

final class AndroidKeyAttestationStatementSupport implements AttestationStatementSupport, CanDispatchEvents
{
    private readonly Decoder $decoder;

    private EventDispatcherInterface $dispatcher;

    public function __construct()
    {
        $this->decoder = Decoder::create();
        $this->dispatcher = new NullEventDispatcher();
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): self
    {
        $this->dispatcher = $eventDispatcher;

        return $this;
    }

    public static function create(): self
    {
        return new self();
    }

    public function name(): string
    {
        return 'android-key';
    }

    /**
     * {@inheritDoc}
     * @param array<string, mixed> $attestation
     */
    public function load(array $attestation): AttestationStatement
    {
        array_key_exists('attStmt', $attestation) || throw AttestationStatementLoadingException::create($attestation);
        foreach (['sig', 'x5c', 'alg'] as $key) {
            array_key_exists($key, $attestation['attStmt']) || throw AttestationStatementLoadingException::create(
                $attestation,
                sprintf('The attestation statement value "%s" is missing.', $key)
            );
        }
        $certificates = $attestation['attStmt']['x5c'];
        (is_countable($certificates) ? count(
            $certificates
        ) : 0) > 0 || throw AttestationStatementLoadingException::create(
            $attestation,
            'The attestation statement value "x5c" must be a list with at least one certificate.'
        );
        $certificates = CertificateToolbox::convertAllDERToPEM($certificates);

        $attestationStatement = AttestationStatement::createBasic(
            $attestation['fmt'],
            $attestation['attStmt'],
            new CertificateTrustPath($certificates)
        );
        $this->dispatcher->dispatch(AttestationStatementLoaded::create($attestationStatement));

        return $attestationStatement;
    }

    /**
     * {@inheritDoc}
     */
    public function isValid(
        string $clientDataJSONHash,
        AttestationStatement $attestationStatement,
        AuthenticatorData $authenticatorData
    ): bool {
        $trustPath = $attestationStatement->getTrustPath();
        $trustPath instanceof CertificateTrustPath || throw InvalidAttestationStatementException::create(
            $attestationStatement,
            'Invalid trust path. Shall contain certificates.'
        );

        $certificates = $trustPath->getCertificates();

        //Decode leaf attestation certificate
        $leaf = $certificates[0];
        $this->checkCertificate($leaf, $clientDataJSONHash, $authenticatorData);

        $signedData = $authenticatorData->getAuthData() . $clientDataJSONHash;
        $alg = $attestationStatement->get('alg');

        return openssl_verify(
            $signedData,
            $attestationStatement->get('sig'),
            $leaf,
            Algorithms::getOpensslAlgorithmFor((int) $alg)
        ) === 1;
    }

    private function checkCertificate(
        string $certificate,
        string $clientDataHash,
        AuthenticatorData $authenticatorData
    ): void {
        $resource = openssl_pkey_get_public($certificate);
        $details = openssl_pkey_get_details($resource);
        is_array($details) || throw AttestationStatementVerificationException::create(
            'Unable to read the certificate'
        );

        //Check that authData publicKey matches the public key in the attestation certificate
        $attestedCredentialData = $authenticatorData->getAttestedCredentialData();
        $attestedCredentialData !== null || throw AttestationStatementVerificationException::create(
            'No attested credential data found'
        );
        $publicKeyData = $attestedCredentialData->getCredentialPublicKey();
        $publicKeyData !== null || throw AttestationStatementVerificationException::create(
            'No attested public key found'
        );
        $publicDataStream = new StringStream($publicKeyData);
        $coseKey = $this->decoder->decode($publicDataStream);
        $coseKey instanceof Normalizable || throw AttestationStatementVerificationException::create(
            'Invalid attested public key found'
        );

        $publicDataStream->isEOF() || throw AttestationStatementVerificationException::create(
            'Invalid public key data. Presence of extra bytes.'
        );
        $publicDataStream->close();
        $publicKey = Key::createFromData($coseKey->normalize());

        ($publicKey instanceof Ec2Key) || ($publicKey instanceof RsaKey) || throw AttestationStatementVerificationException::create(
            'Unsupported key type'
        );
        $publicKey->asPEM() === $details['key'] || throw AttestationStatementVerificationException::create(
            'Invalid key'
        );

        /*---------------------------*/
        $certDetails = openssl_x509_parse($certificate);

        //Find Android KeyStore Extension with OID "1.3.6.1.4.1.11129.2.1.17" in certificate extensions
        is_array(
            $certDetails
        ) || throw AttestationStatementVerificationException::create('The certificate is not valid');
        array_key_exists('extensions', $certDetails) || throw AttestationStatementVerificationException::create(
            'The certificate has no extension'
        );
        is_array($certDetails['extensions']) || throw AttestationStatementVerificationException::create(
            'The certificate has no extension'
        );
        array_key_exists(
            '1.3.6.1.4.1.11129.2.1.17',
            $certDetails['extensions']
        ) || throw AttestationStatementVerificationException::create(
            'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is missing'
        );
        $extension = $certDetails['extensions']['1.3.6.1.4.1.11129.2.1.17'];
        $extensionAsAsn1 = ASNObject::fromBinary($extension);
        $extensionAsAsn1 instanceof Sequence || throw AttestationStatementVerificationException::create(
            'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid'
        );
        $objects = $extensionAsAsn1->getChildren();

        //Check that attestationChallenge is set to the clientDataHash.
        array_key_exists(4, $objects) || throw AttestationStatementVerificationException::create(
            'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid'
        );
        $objects[4] instanceof OctetString || throw AttestationStatementVerificationException::create(
            'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid'
        );
        $clientDataHash === hex2bin(
            (string) ($objects[4])->getContent()
        ) || throw AttestationStatementVerificationException::create('The client data hash is not valid');

        //Check that both teeEnforced and softwareEnforced structures don't contain allApplications(600) tag.
        array_key_exists(6, $objects) || throw AttestationStatementVerificationException::create(
            'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid'
        );
        $softwareEnforcedFlags = $objects[6];
        $softwareEnforcedFlags instanceof Sequence || throw AttestationStatementVerificationException::create(
            'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid'
        );
        $this->checkAbsenceOfAllApplicationsTag($softwareEnforcedFlags);

        array_key_exists(7, $objects) || throw AttestationStatementVerificationException::create(
            'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid'
        );
        $teeEnforcedFlags = $objects[6];
        $teeEnforcedFlags instanceof Sequence || throw AttestationStatementVerificationException::create(
            'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid'
        );
        $this->checkAbsenceOfAllApplicationsTag($teeEnforcedFlags);
    }

    private function checkAbsenceOfAllApplicationsTag(Sequence $sequence): void
    {
        foreach ($sequence->getChildren() as $tag) {
            $tag instanceof ExplicitlyTaggedObject || throw AttestationStatementVerificationException::create(
                'Invalid tag'
            );
            (int) $tag->getTag() !== 600 || throw AttestationStatementVerificationException::create(
                'Forbidden tag 600 found'
            );
        }
    }
}
