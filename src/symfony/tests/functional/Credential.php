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

namespace Webauthn\Bundle\Tests\Functional;

use Ramsey\Uuid\UuidInterface;
use Webauthn\AttestedCredentialData;
use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity(repositoryClass="Webauthn\Bundle\Tests\Functional\CredentialRepository")
 */
class Credential
{
    /**
     * @ORM\Id
     * @ORM\Column(type="string", length=255)
     */
    private $id;

    /**
     * @ORM\Column(type="blob", length=255)
     */
    private $credential_id;

    /**
     * @ORM\Column(type="attested_credential_data")
     */
    private $attested_credential_data;

    /**
     * @ORM\Column(type="integer")
     */
    private $counter;

    public function __construct(UuidInterface $uuid, AttestedCredentialData $attested_credential_data, int $counter)
    {
        $this->id = $uuid->toString();
        $this->credential_id = $attested_credential_data->getCredentialId();
        $this->attested_credential_data = $attested_credential_data;
        $this->counter = $counter;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getAttestedCredentialData(): AttestedCredentialData
    {
        return $this->attested_credential_data;
    }

    public function getCounter(): int
    {
        return $this->counter;
    }

    public function setCounter(int $counter): void
    {
        $this->counter = $counter;
    }
}
