<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use function array_key_exists;
use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\Normalizable;
use function is_array;
use function ord;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Uid\Uuid;
use Throwable;
use function unpack;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader;
use Webauthn\AuthenticatorData;
use Webauthn\Event\AttestationObjectLoaded;
use Webauthn\Exception\InvalidDataException;
use Webauthn\MetadataService\CanLogData;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\Event\NullEventDispatcher;
use Webauthn\StringStream;
use Webauthn\Util\Base64;

class AttestationObjectLoader implements CanDispatchEvents, CanLogData
{
    private const FLAG_AT = 0b01000000;

    private const FLAG_ED = 0b10000000;

    private readonly Decoder $decoder;

    private LoggerInterface $logger;

    private EventDispatcherInterface $dispatcher;

    public function __construct(
        private readonly AttestationStatementSupportManager $attestationStatementSupportManager
    ) {
        $this->decoder = Decoder::create();
        $this->logger = new NullLogger();
        $this->dispatcher = new NullEventDispatcher();
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->dispatcher = $eventDispatcher;
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
            $parsed instanceof Normalizable || throw InvalidDataException::create(
                $parsed,
                'Invalid attestation object. Unexpected object.'
            );
            $attestationObject = $parsed->normalize();
            $stream->isEOF() || throw InvalidDataException::create(
                null,
                'Invalid attestation object. Presence of extra bytes.'
            );
            $stream->close();
            is_array($attestationObject) || throw InvalidDataException::create(
                $attestationObject,
                'Invalid attestation object'
            );
            array_key_exists('authData', $attestationObject) || throw InvalidDataException::create(
                $attestationObject,
                'Invalid attestation object'
            );
            array_key_exists('fmt', $attestationObject) || throw InvalidDataException::create(
                $attestationObject,
                'Invalid attestation object'
            );
            array_key_exists('attStmt', $attestationObject) || throw InvalidDataException::create(
                $attestationObject,
                'Invalid attestation object'
            );
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
                $credentialPublicKey instanceof MapObject || throw InvalidDataException::create(
                    $credentialPublicKey,
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
            $authDataStream->isEOF() || throw InvalidDataException::create(
                null,
                'Invalid authentication data. Presence of extra bytes.'
            );
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
            $this->dispatcher->dispatch(AttestationObjectLoaded::create($attestationObject));

            return $attestationObject;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }
}
