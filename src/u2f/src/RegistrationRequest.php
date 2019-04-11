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
use JsonSerializable;

class RegistrationRequest implements JsonSerializable
{
    private const PROTOCOL_VERSION = 'U2F_V2';

    /**
     * @var string
     */
    private $applicationId;

    /**
     * @var string
     */
    private $challenge;

    /**
     * @var RegisteredKey[]
     */
    private $registeredKeys = [];

    public function __construct(string $applicationId, array $registeredKeys = [])
    {
        $this->applicationId = $applicationId;
        $this->challenge = random_bytes(32);
        foreach ($registeredKeys as $registeredKey) {
            Assertion::isInstanceOf($registeredKey, RegisteredKey::class, 'Invalid registered keys list.');
            $this->registeredKeys[Base64Url::encode((string) $registeredKey->getKeyHandler())] = $registeredKey;
        }
    }

    public function getApplicationId(): string
    {
        return $this->applicationId;
    }

    public function getChallenge(): string
    {
        return $this->challenge;
    }

    /**
     * @return RegisteredKey[]
     */
    public function getRegisteredKeys(): array
    {
        return $this->registeredKeys;
    }

    public function jsonSerialize(): array
    {
        return [
            'appId' => $this->applicationId,
            'registerRequests' => [
                ['version' => self::PROTOCOL_VERSION, 'challenge' => Base64Url::encode($this->challenge)],
            ],
            'registeredKeys' => array_values($this->registeredKeys),
        ];
    }
}
