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

namespace Webauthn;

use Assert\Assertion;
use JsonSerializable;
use function Safe\base64_decode;
use function Safe\preg_replace;

/**
 * @see https://www.w3.org/TR/webauthn/#sec-attested-credential-data
 */
class AttestedCredentialData implements JsonSerializable
{
    /**
     * @var string
     */
    private $aaguid;

    /**
     * @var string
     */
    private $credentialId;

    /**
     * @var string|null
     */
    private $credentialPublicKey;

    public function __construct(string $aaguid, string $credentialId, ?string $credentialPublicKey)
    {
        $this->aaguid = $aaguid;
        $this->credentialId = $credentialId;
        $this->credentialPublicKey = $credentialPublicKey;
    }

    public function getAaguid(): string
    {
        return $this->aaguid;
    }

    public function getAaguidAsUuid(): string
    {
        $data = bin2hex($this->aaguid);

        return preg_replace('/([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{12})/', '$1-$2-$3-$4-$5', $data);
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function getCredentialPublicKey(): ?string
    {
        return $this->credentialPublicKey;
    }

    public static function createFromArray(array $json): self
    {
        Assertion::keyExists($json, 'aaguid', 'Invalid input. "aaguid" is missing.');
        Assertion::keyExists($json, 'credentialId', 'Invalid input. "credentialId" is missing.');

        return new self(
            base64_decode($json['aaguid'], true),
            base64_decode($json['credentialId'], true),
            isset($json['credentialPublicKey']) ? base64_decode($json['credentialPublicKey'], true) : null
        );
    }

    public function jsonSerialize(): array
    {
        $result = [
            'aaguid' => base64_encode($this->aaguid),
            'credentialId' => base64_encode($this->credentialId),
        ];
        if (null !== $this->credentialPublicKey) {
            $result['credentialPublicKey'] = base64_encode($this->credentialPublicKey);
        }

        return $result;
    }
}
