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

namespace Webauthn;

use Assert\Assertion;

/**
 * @see https://www.w3.org/TR/webauthn/#sec-attested-credential-data
 */
class AttestedCredentialData implements \JsonSerializable
{
    private $aaguid;

    private $credentialId;

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

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function getCredentialPublicKey(): ?string
    {
        return $this->credentialPublicKey;
    }

    public static function createFromJson(string $json): self
    {
        $data = \Safe\json_decode($json, true);
        Assertion::isArray($data, 'Invalid input.');
        Assertion::keyExists($data, 'aaguid', 'Invalid input.');
        Assertion::keyExists($data, 'credentialId', 'Invalid input.');

        return new self(
            \Safe\base64_decode($data['aaguid'], true),
            \Safe\base64_decode($data['credentialId'], true),
            $data['credentialPublicKey'] ? \Safe\base64_decode($data['credentialPublicKey'], true) : null
        );
    }

    public function jsonSerialize()
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
