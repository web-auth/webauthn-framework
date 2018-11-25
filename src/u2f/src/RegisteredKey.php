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

use Base64Url\Base64Url;

class RegisteredKey implements \JsonSerializable
{
    private $version;

    private $keyHandler;

    private $publicKey;

    private $attestationCertificate;

    public function __construct(string $version, KeyHandler $keyHandler, PublicKey $publicKey, string $attestationCertificate)
    {
        $this->version = $version;
        $this->keyHandler = $keyHandler;
        $this->publicKey = $publicKey;
        $this->attestationCertificate = $attestationCertificate;
    }

    /**
     * @return RegisteredKey
     */
    public static function createFromJson(string $data, int $options = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE): self
    {
        try {
            $json = \Safe\json_decode($data, true, 512, $options);
            extract($json);

            return new self(
                $version,
                new KeyHandler(Base64Url::decode($keyHandle)),
                new PublicKey(Base64Url::decode($publicKey)),
                $attestationCertificate
            );
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Invalid data', 0, $e);
        }
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

    public function jsonSerialize()
    {
        return [
            'version' => $this->version,
            'keyHandle' => $this->keyHandler,
            'publicKey' => $this->publicKey,
            'attestationCertificate' => $this->attestationCertificate,
        ];
    }
}
