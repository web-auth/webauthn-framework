<?php

declare(strict_types=1);

namespace Webauthn;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\Exception\InvalidDataException;
use Webauthn\MetadataService\CanLogData;
use Webauthn\Util\Base64;
use function array_key_exists;
use function is_array;
use function is_string;
use const JSON_THROW_ON_ERROR;

class PublicKeyCredentialLoader implements CanLogData
{
    private LoggerInterface $logger;

    public function __construct(
        private readonly AttestationObjectLoader $attestationObjectLoader,
        private readonly null|SerializerInterface $serializer = null,
    ) {
        $this->logger = new NullLogger();
    }

    public static function create(
        AttestationObjectLoader $attestationObjectLoader,
        null|SerializerInterface $serializer = null
    ): self {
        return new self($attestationObjectLoader, $serializer);
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * @param mixed[] $json
     * @deprecated since 4.8.0 and will be removed in 5.0.0. Please use {self::load} instead
     * @infection-ignore-all
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

            $publicKeyCredential = PublicKeyCredential::create(
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
            if ($this->serializer === null) {
                $json = json_decode($data, true, flags: JSON_THROW_ON_ERROR);

                return $this->loadArray($json);
            }

            return $this->serializer->deserialize($data, PublicKeyCredential::class, 'json');
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
        /** @var string[] $transports */
        $transports = $response['transports'] ?? [];
        is_array($transports) || throw InvalidDataException::create(
            $response,
            'Invalid data. The parameter "transports" is invalid'
        );
        switch (true) {
            case array_key_exists('attestationObject', $response):
                is_string($response['attestationObject']) || throw InvalidDataException::create(
                    $response,
                    'Invalid data. The parameter "attestationObject" is invalid'
                );
                $attestationObject = $this->attestationObjectLoader->load($response['attestationObject']);

                return AuthenticatorAttestationResponse::create(CollectedClientData::createFormJson(
                    $response['clientDataJSON']
                ), $attestationObject, $transports);
            case array_key_exists('authenticatorData', $response) && array_key_exists('signature', $response):
                $authDataLoader = AuthenticatorDataLoader::create();
                $authData = Base64UrlSafe::decodeNoPadding($response['authenticatorData']);
                $authenticatorData = $authDataLoader->load($authData);

                try {
                    $signature = Base64::decode($response['signature']);
                } catch (Throwable $e) {
                    throw InvalidDataException::create(
                        $response['signature'],
                        'The signature shall be Base64 Url Safe encoded',
                        $e
                    );
                }
                $userHandle = $response['userHandle'] ?? null;
                if ($userHandle !== '' && $userHandle !== null) {
                    $userHandle = Base64::decode($userHandle);
                }

                return AuthenticatorAssertionResponse::create(
                    CollectedClientData::createFormJson($response['clientDataJSON']),
                    $authenticatorData,
                    $signature,
                    $userHandle
                );
            default:
                throw InvalidDataException::create($response, 'Unable to create the response object');
        }
    }
}
