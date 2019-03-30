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

class ClientData
{
    /**
     * @var string
     */
    private $rawData;

    /**
     * @var string
     */
    private $typ;

    /**
     * @var string
     */
    private $challenge;

    /**
     * @var string
     */
    private $origin;

    /**
     * @var string
     */
    private $cid_pubkey;

    public function __construct(string $clientData)
    {
        $this->rawData = Base64Url::decode($clientData);
        $clientData = \Safe\json_decode($this->rawData, true);
        Assertion::isArray($clientData, 'Invalid client data.');
        foreach (['typ', 'challenge', 'origin'] as $key) {
            Assertion::keyExists($clientData, $key, 'Invalid client data.');
        }
        $this->typ = $clientData['typ'];
        $this->challenge = $clientData['challenge'];
        $this->origin = $clientData['origin'];
        $this->cid_pubkey = $clientData['cid_pubkey'] ?? 'unused';
    }

    public function getRawData(): string
    {
        return $this->rawData;
    }

    public function getType(): string
    {
        return $this->typ;
    }

    public function getChallenge(): string
    {
        return Base64Url::decode($this->challenge);
    }

    public function getOrigin(): string
    {
        return $this->origin;
    }

    public function getChannelIdPublicKey(): string
    {
        return $this->cid_pubkey;
    }
}
