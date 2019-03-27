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

namespace U2F;

use Assert\Assertion;
use Base64Url\Base64Url;

class RegisteredKey implements \JsonSerializable
{
    /**
     * @var string
     */
    private $version;

    /**
     * @var KeyHandler
     */
    private $keyHandler;

    /**
     * @var PublicKey
     */
    private $publicKey;

    /**
     * @var string
     */
    private $attestationCertificate;

    public function __construct(string $version, KeyHandler $keyHandler, PublicKey $publicKey, string $attestationCertificate)
    {
        $this->version = $version;
        $this->keyHandler = $keyHandler;
        $this->publicKey = $publicKey;
        $this->attestationCertificate = $attestationCertificate;
    }

    /**
     * @deprecated will be removed in v2.0. Use "createFromArray" or "createFromString" instead
     */
    public static function createFromJson(string $json, int $options = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE): self
    {
        $data = \Safe\json_decode($json, true, 512, $options);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    public static function createFromString(string $data): self
    {
        $data = \Safe\json_decode($data, true);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    public static function createFromArray(array $data): self
    {
        foreach (['version', 'keyHandle', 'publicKey', 'attestationCertificate'] as $key) {
            Assertion::keyExists($data, $key, \Safe\sprintf('The key "%s" is missing', $key));
        }

        return new self(
            $data['version'],
            new KeyHandler(Base64Url::decode($data['keyHandle'])),
            new PublicKey(Base64Url::decode($data['publicKey'])),
            $data['attestationCertificate']
        );
    }

    public function getVersion(): string
    {
        return $this->version;
    }

    public function getKeyHandler(): KeyHandler
    {
        return $this->keyHandler;
    }

    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    public function getPublicKeyAsPem(): string
    {
        $der = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
        $der .= "\0".$this->publicKey;

        $pem = '-----BEGIN PUBLIC KEY-----'.PHP_EOL;
        $pem .= chunk_split(base64_encode($der), 64, PHP_EOL);
        $pem .= '-----END PUBLIC KEY-----'.PHP_EOL;

        return $pem;
    }

    public function getAttestationCertificate(): string
    {
        return $this->attestationCertificate;
    }

    public function jsonSerialize(): array
    {
        return [
            'version' => $this->version,
            'keyHandle' => $this->keyHandler,
            'publicKey' => $this->publicKey,
            'attestationCertificate' => $this->attestationCertificate,
        ];
    }
}
