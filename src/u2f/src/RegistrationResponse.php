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

namespace U2F;

use Assert\Assertion;
use Base64Url\Base64Url;
use InvalidArgumentException;
use function Safe\fclose;
use function Safe\fopen;
use function Safe\fread;
use function Safe\fwrite;
use function Safe\rewind;

class RegistrationResponse
{
    private const SUPPORTED_PROTOCOL_VERSIONS = ['U2F_V2'];
    private const PUBLIC_KEY_LENGTH = 65;

    /**
     * @var ClientData
     */
    private $clientData;

    /**
     * @var RegisteredKey
     */
    private $registeredKey;

    /**
     * @var string
     */
    private $signature;

    public function __construct(array $data)
    {
        Assertion::false(\array_key_exists('errorCode', $data) && 0 !== $data['errorCode'], 'Invalid response.');

        $this->checkVersion($data);
        $clientData = $this->retrieveClientData($data);
        Assertion::eq('navigator.id.finishEnrollment', $clientData->getType(), 'Invalid response.');
        list($publicKey, $keyHandle, $pemCert, $signature) = $this->extractKeyData($data);

        $this->clientData = $clientData;
        $this->registeredKey = new RegisteredKey($data['version'], $keyHandle, $publicKey, $pemCert);
        $this->signature = $signature;
    }

    public function getClientData(): ClientData
    {
        return $this->clientData;
    }

    public function getRegisteredKey(): RegisteredKey
    {
        return $this->registeredKey;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    private function retrieveClientData(array $data): ClientData
    {
        if (!\array_key_exists('clientData', $data) || !\is_string($data['clientData'])) {
            throw new InvalidArgumentException('Invalid response.');
        }

        return new ClientData($data['clientData']);
    }

    private function checkVersion(array $data): void
    {
        Assertion::false(!\array_key_exists('version', $data) || !\is_string($data['version']), 'Invalid response.');
        Assertion::false(!\in_array($data['version'], self::SUPPORTED_PROTOCOL_VERSIONS, true), 'Unsupported protocol version.');
    }

    private function extractKeyData(array $data): array
    {
        Assertion::false(!\array_key_exists('registrationData', $data) || !\is_string($data['registrationData']), 'Invalid response.');
        $stream = fopen('php://memory', 'r+');
        $registrationData = Base64Url::decode($data['registrationData']);
        fwrite($stream, $registrationData);
        rewind($stream);

        $reservedByte = fread($stream, 1);
        try {
            // 1 byte reserved with value x05
            Assertion::eq("\x05", $reservedByte, 'Bad reserved byte.');

            $publicKey = fread($stream, self::PUBLIC_KEY_LENGTH); // 65 bytes for the public key
            Assertion::eq(self::PUBLIC_KEY_LENGTH, mb_strlen($publicKey, '8bit'), 'Bad public key length.');

            $keyHandleLength = fread($stream, 1); // 1 byte for the key handle length
            Assertion::notEq(0, \ord($keyHandleLength), 'Bad key handle length.');

            $keyHandle = fread($stream, \ord($keyHandleLength)); // x bytes for the key handle
            Assertion::eq(mb_strlen($keyHandle, '8bit'), \ord($keyHandleLength), 'Bad key handle.');

            $certHeader = fread($stream, 4); // 4 bytes for the certificate header
            Assertion::eq(4, mb_strlen($certHeader, '8bit'), 'Bad certificate header.');

            $highOrder = \ord($certHeader[2]) << 8;
            $lowOrder = \ord($certHeader[3]);
            $certLength = $highOrder + $lowOrder;
            $certBody = fread($stream, $certLength); // x bytes for the certificate
            Assertion::eq(mb_strlen($certBody, '8bit'), $certLength, 'Bad certificate.');
        } catch (\Throwable $throwable) {
            fclose($stream);
            throw $throwable;
        }

        $pemCert = $this->convertDERToPEM($certHeader.$certBody);
        $signature = ''; // The rest is the signature
        while (!feof($stream)) {
            $signature .= fread($stream, 1024);
        }
        fclose($stream);

        return [
            new PublicKey($publicKey),
            new KeyHandler($keyHandle),
            $pemCert,
            $signature,
        ];
    }

    public function isValid(RegistrationRequest $challenge): bool
    {
        if (!hash_equals($challenge->getChallenge(), $this->clientData->getChallenge())) {
            return false;
        }
        if (!hash_equals($challenge->getApplicationId(), $this->clientData->getOrigin())) {
            return false;
        }

        $dataToVerify = "\0";
        $dataToVerify .= hash('sha256', $this->clientData->getOrigin(), true);
        $dataToVerify .= hash('sha256', $this->clientData->getRawData(), true);
        $dataToVerify .= $this->registeredKey->getKeyHandler();
        $dataToVerify .= $this->registeredKey->getPublicKey();

        return 1 === openssl_verify($dataToVerify, $this->signature, $this->registeredKey->getAttestationCertificate(), OPENSSL_ALGO_SHA256);
    }

    private function convertDERToPEM(string $publicKey): string
    {
        $derCertificate = $this->unusedBytesFix($publicKey);
        $pemCert = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $pemCert .= chunk_split(base64_encode($derCertificate), 64, PHP_EOL);
        $pemCert .= '-----END CERTIFICATE-----'.PHP_EOL;

        return $pemCert;
    }

    private function unusedBytesFix(string $derCertificate): string
    {
        $certificateHash = hash('sha256', $derCertificate);
        if (\in_array($certificateHash, $this->getCertificateHashes(), true)) {
            $derCertificate[mb_strlen($derCertificate, '8bit') - 257] = "\0";
        }

        return $derCertificate;
    }

    /**
     * @return string[]
     */
    private function getCertificateHashes(): array
    {
        return [
            '349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8',
            'dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f',
            '1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae',
            'd0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb',
            '6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897',
            'ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511',
        ];
    }
}
