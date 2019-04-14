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

class SignatureRequest implements JsonSerializable
{
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

    public function __construct(string $applicationId, array $registeredKeys)
    {
        $this->applicationId = $applicationId;
        foreach ($registeredKeys as $registeredKey) {
            Assertion::isInstanceOf($registeredKey, RegisteredKey::class, 'Invalid registered keys list.');
            $this->registeredKeys[Base64Url::encode((string) $registeredKey->getKeyHandler())] = $registeredKey;
        }
        $this->challenge = random_bytes(32);
    }

    public function addRegisteredKey(RegisteredKey $registeredKey): void
    {
        $this->registeredKeys[Base64Url::encode((string) $registeredKey->getKeyHandler())] = $registeredKey;
    }

    public function hasRegisteredKey(KeyHandler $keyHandle): bool
    {
        return \array_key_exists(Base64Url::encode($keyHandle->getValue()), $this->registeredKeys);
    }

    public function getRegisteredKey(KeyHandler $keyHandle): RegisteredKey
    {
        Assertion::true($this->hasRegisteredKey($keyHandle), 'Unsupported key handle.');

        return $this->registeredKeys[Base64Url::encode($keyHandle->getValue())];
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
            'challenge' => Base64Url::encode($this->challenge),
            'registeredKeys' => array_values($this->registeredKeys),
        ];
    }
}
