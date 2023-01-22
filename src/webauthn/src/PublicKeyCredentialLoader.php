<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use CBOR\Decoder;
use CBOR\MapObject;
use function is_array;
use function is_string;
use const JSON_THROW_ON_ERROR;
use function ord;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Uid\Uuid;
use Throwable;
use function unpack;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader;
use Webauthn\Exception\InvalidDataException;
use Webauthn\MetadataService\CanLogData;
use Webauthn\Util\Base64;

class PublicKeyCredentialLoader implements CanLogData
{
    private const FLAG_AT = 0b01000000;

    private const FLAG_ED = 0b10000000;

    private readonly Decoder $decoder;

    private LoggerInterface $logger;

    public function __construct(
        private readonly AttestationObjectLoader $attestationObjectLoader
    ) {
        $this->decoder = Decoder::create();
        $this->logger = new NullLogger();
    }

    public static function create(AttestationObjectLoader $attestationObjectLoader): self
    {
        return new self($attestationObjectLoader);
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * @param mixed[] $json
     */
    public function loadArray(array $json): PublicKeyCredential
    {
        $this->logger->info('Trying to load data from an array', [
            'data' => $json,
        ]);
        try {
            foreach (['id', 'rawId', 'type'] as $key) {
                array_key_exists($key, $json) || throw InvalidDataException::create($json, sprintf(
                    'The parameter "%s" is missing',
                    $key
                ));
                is_string($json[$key]) || throw InvalidDataException::create($json, sprintf(
                    'The parameter "%s" shall be a string',
                    $key
                ));
            }
            array_key_exists('response', $json) || throw InvalidDataException::create(
                $json,
                'The parameter "response" is missing'
            );
            is_array($json['response']) || throw InvalidDataException::create(
                $json,
                'The parameter "response" shall be an array'
            );
            $json['type'] === 'public-key' || throw InvalidDataException::create($json, sprintf(
                'Unsupported type "%s"',
                $json['type']
            ));

            $id = Base64UrlSafe::decodeNoPadding($json['id']);
            $rawId = Base64::decode($json['rawId']);
            hash_equals($id, $rawId) || throw InvalidDataException::create($json, 'Invalid ID');

            $publicKeyCredential = new PublicKeyCredential(
                $json['id'],
                $json['type'],
                $rawId,
                $this->createResponse($json['response'])
            );
            $this->logger->info('The data has been loaded');
            $this->logger->debug('Public Key Credential', [
                'publicKeyCredential' => $publicKeyCredential,
            ]);

            return $publicKeyCredential;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    public function load(string $data): PublicKeyCredential
    {
        $this->logger->info('Trying to load data from a string', [
            'data' => $data,
        ]);
        try {
            $json = json_decode($data, true, 512, JSON_THROW_ON_ERROR);

            return $this->loadArray($json);
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw InvalidDataException::create($data, 'Unable to load the data', $throwable);
        }
    }

    /**
     * @param mixed[] $response
     */
    private function createResponse(array $response): AuthenticatorResponse
    {
        array_key_exists('clientDataJSON', $response) || throw InvalidDataException::create(
            $response,
            'Invalid data. The parameter "clientDataJSON" is missing'
        );
        is_string($response['clientDataJSON']) || throw InvalidDataException::create(
            $response,
            'Invalid data. The parameter "clientDataJSON" is invalid'
        );
        $userHandle = $response['userHandle'] ?? null;
        $userHandle === null || is_string($userHandle) || throw InvalidDataException::create(
            $response,
            'Invalid data. The parameter "userHandle" is invalid'
        );
        switch (true) {
            case array_key_exists('attestationObject', $response):
                is_string($response['attestationObject']) || throw InvalidDataException::create(
                    $response,
                    'Invalid data. The parameter "attestationObject   " is invalid'
                );
                $attestationObject = $this->attestationObjectLoader->load($response['attestationObject']);

                return new AuthenticatorAttestationResponse(CollectedClientData::createFormJson(
                    $response['clientDataJSON']
                ), $attestationObject);
            case array_key_exists('authenticatorData', $response) && array_key_exists('signature', $response):
                $authData = Base64UrlSafe::decodeNoPadding($response['authenticatorData']);

                $authDataStream = new StringStream($authData);
                $rp_id_hash = $authDataStream->read(32);
                $flags = $authDataStream->read(1);
                $signCount = $authDataStream->read(4);
                $signCount = unpack('N', $signCount);

                $attestedCredentialData = null;
                if (0 !== (ord($flags) & self::FLAG_AT)) {
                    $aaguid = Uuid::fromBinary($authDataStream->read(16));
                    $credentialLength = $authDataStream->read(2);
                    $credentialLength = unpack('n', $credentialLength);
                    $credentialId = $authDataStream->read($credentialLength[1]);
                    $credentialPublicKey = $this->decoder->decode($authDataStream);
                    $credentialPublicKey instanceof MapObject || throw InvalidDataException::create(
                        $authData,
                        'The data does not contain a valid credential public key.'
                    );
                    $attestedCredentialData = new AttestedCredentialData(
                        $aaguid,
                        $credentialId,
                        (string) $credentialPublicKey
                    );
                }

                $extension = null;
                if (0 !== (ord($flags) & self::FLAG_ED)) {
                    $extension = $this->decoder->decode($authDataStream);
                    $extension = AuthenticationExtensionsClientOutputsLoader::load($extension);
                }
                $authDataStream->isEOF() || throw InvalidDataException::create(
                    $authData,
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

                try {
                    $signature = Base64::decode($response['signature']);
                } catch (Throwable $e) {
                    throw InvalidDataException::create(
                        $response['signature'],
                        'The signature shall be Base64 Url Safe encoded',
                        $e
                    );
                }

                return new AuthenticatorAssertionResponse(
                    CollectedClientData::createFormJson($response['clientDataJSON']),
                    $authenticatorData,
                    $signature,
                    $response['userHandle'] ?? null
                );
            default:
                throw InvalidDataException::create($response, 'Unable to create the response object');
        }
    }
}
