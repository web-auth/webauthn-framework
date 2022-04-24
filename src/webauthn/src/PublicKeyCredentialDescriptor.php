<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use function count;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\Util\Base64;

class PublicKeyCredentialDescriptor implements JsonSerializable
{
    final public const CREDENTIAL_TYPE_PUBLIC_KEY = 'public-key';

    final public const AUTHENTICATOR_TRANSPORT_USB = 'usb';

    final public const AUTHENTICATOR_TRANSPORT_NFC = 'nfc';

    final public const AUTHENTICATOR_TRANSPORT_BLE = 'ble';

    final public const AUTHENTICATOR_TRANSPORT_CABLE = 'cable';

    final public const AUTHENTICATOR_TRANSPORT_INTERNAL = 'internal';

    /**
     * @param string[] $transports
     */
    public function __construct(
        protected string $type,
        protected string $id,
        protected array $transports = []
    ) {
    }

    /**
     * @param string[] $transports
     */
    public static function create(string $type, string $id, array $transports = []): self
    {
        return new self($type, $id, $transports);
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getId(): string
    {
        return $this->id;
    }

    /**
     * @return string[]
     */
    public function getTransports(): array
    {
        return $this->transports;
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
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

        $id = Base64::decodeUrlSafe($json['id']);

        return new self($json['type'], $id, $json['transports'] ?? []);
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = [
            'type' => $this->type,
            'id' => Base64UrlSafe::encodeUnpadded($this->id),
        ];
        if (count($this->transports) !== 0) {
            $json['transports'] = $this->transports;
        }

        return $json;
    }
}
