<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use Assert\Assertion;
use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\Normalizable;
use function ord;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use function Safe\unpack;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader;
use Webauthn\AuthenticatorData;
use Webauthn\StringStream;
use Webauthn\Util\Base64;

class AttestationObjectLoader
{
    private const FLAG_AT = 0b01000000;

    private const FLAG_ED = 0b10000000;

    private readonly Decoder $decoder;

    private LoggerInterface $logger;

    public function __construct(
        private readonly AttestationStatementSupportManager $attestationStatementSupportManager
    ) {
        $this->decoder = Decoder::create();
        $this->logger = new NullLogger();
    }

    public static function create(AttestationStatementSupportManager $attestationStatementSupportManager): self
    {
        return new self($attestationStatementSupportManager);
    }

    public function load(string $data): AttestationObject
    {
        try {
            $this->logger->info('Trying to load the data', [
                'data' => $data,
            ]);
            $decodedData = Base64::decode($data);
            $stream = new StringStream($decodedData);
            $parsed = $this->decoder->decode($stream);

            $this->logger->info('Loading the Attestation Statement');
            Assertion::isInstanceOf($parsed, Normalizable::class, 'Invalid attestation object. Unexpected object.');
            $attestationObject = $parsed->normalize();
            Assertion::true($stream->isEOF(), 'Invalid attestation object. Presence of extra bytes.');
            $stream->close();
            Assertion::isArray($attestationObject, 'Invalid attestation object');
            Assertion::keyExists($attestationObject, 'authData', 'Invalid attestation object');
            Assertion::keyExists($attestationObject, 'fmt', 'Invalid attestation object');
            Assertion::keyExists($attestationObject, 'attStmt', 'Invalid attestation object');
            $authData = $attestationObject['authData'];

            $attestationStatementSupport = $this->attestationStatementSupportManager->get($attestationObject['fmt']);
            $attestationStatement = $attestationStatementSupport->load($attestationObject);
            $this->logger->info('Attestation Statement loaded');
            $this->logger->debug('Attestation Statement loaded', [
                'attestationStatement' => $attestationStatement,
            ]);

            $authDataStream = new StringStream($authData);
            $rp_id_hash = $authDataStream->read(32);
            $flags = $authDataStream->read(1);
            $signCount = $authDataStream->read(4);
            $signCount = unpack('N', $signCount);
            $this->logger->debug(sprintf('Signature counter: %d', $signCount[1]));

            $attestedCredentialData = null;
            if (0 !== (ord($flags) & self::FLAG_AT)) {
                $this->logger->info('Attested Credential Data is present');
                $aaguid = Uuid::fromBinary($authDataStream->read(16));
                $credentialLength = $authDataStream->read(2);
                $credentialLength = unpack('n', $credentialLength);
                $credentialId = $authDataStream->read($credentialLength[1]);
                $credentialPublicKey = $this->decoder->decode($authDataStream);
                Assertion::isInstanceOf(
                    $credentialPublicKey,
                    MapObject::class,
                    'The data does not contain a valid credential public key.'
                );
                $attestedCredentialData = new AttestedCredentialData(
                    $aaguid,
                    $credentialId,
                    (string) $credentialPublicKey
                );
                $this->logger->info('Attested Credential Data loaded');
                $this->logger->debug('Attested Credential Data loaded', [
                    'at' => $attestedCredentialData,
                ]);
            }

            $extension = null;
            if (0 !== (ord($flags) & self::FLAG_ED)) {
                $this->logger->info('Extension Data loaded');
                $extension = $this->decoder->decode($authDataStream);
                $extension = AuthenticationExtensionsClientOutputsLoader::load($extension);
                $this->logger->info('Extension Data loaded');
                $this->logger->debug('Extension Data loaded', [
                    'ed' => $extension,
                ]);
            }
            Assertion::true($authDataStream->isEOF(), 'Invalid authentication data. Presence of extra bytes.');
            $authDataStream->close();

            $authenticatorData = new AuthenticatorData(
                $authData,
                $rp_id_hash,
                $flags,
                $signCount[1],
                $attestedCredentialData,
                $extension
            );
            $attestationObject = new AttestationObject($data, $attestationStatement, $authenticatorData);
            $this->logger->info('Attestation Object loaded');
            $this->logger->debug('Attestation Object', [
                'ed' => $attestationObject,
            ]);

            return $attestationObject;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }
}
