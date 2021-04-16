<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use Assert\Assertion;
use Base64Url\Base64Url;
use function count;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;
use function Safe\json_decode;

class PublicKeyCredentialDescriptor implements JsonSerializable
{
    public const CREDENTIAL_TYPE_PUBLIC_KEY = 'public-key';

    public const AUTHENTICATOR_TRANSPORT_USB = 'usb';
    public const AUTHENTICATOR_TRANSPORT_NFC = 'nfc';
    public const AUTHENTICATOR_TRANSPORT_BLE = 'ble';
    public const AUTHENTICATOR_TRANSPORT_INTERNAL = 'internal';

    /*
     * @var string[]
     */

    #[Pure]
    public function __construct(protected string $type, protected string $id, protected array $transports = [])
    {
    }

    #[Pure]
    public static function create(string $type, string $id, array $transports = []): self
    {
        return new self($type, $id, $transports);
    }

    #[Pure]
    public function getType(): string
    {
        return $this->type;
    }

    #[Pure]
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * @return string[]
     */
    #[Pure]
    public function getTransports(): array
    {
        return $this->transports;
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        Assertion::keyExists($json, 'type', 'Invalid input. "type" is missing.');
        Assertion::keyExists($json, 'id', 'Invalid input. "id" is missing.');

        return new self(
            $json['type'],
            Base64Url::decode($json['id']),
            $json['transports'] ?? []
        );
    }

    #[Pure]
    #[ArrayShape(['type' => 'string', 'id' => 'string', 'transports' => 'array'])]
    public function jsonSerialize(): array
    {
        $json = [
            'type' => $this->type,
            'id' => Base64Url::encode($this->id),
        ];
        if (0 !== count($this->transports)) {
            $json['transports'] = $this->transports;
        }

        return $json;
    }
}
