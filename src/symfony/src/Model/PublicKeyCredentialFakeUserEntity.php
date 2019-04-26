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

namespace Webauthn\Bundle\Model;

use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialUserEntity;

final class PublicKeyCredentialFakeUserEntity extends PublicKeyCredentialUserEntity
{
    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private $credentials;

    /**
     * @param PublicKeyCredentialDescriptor[] $credentials
     */
    public function __construct(string $name, string $id, string $displayName, array $credentials, ?string $icon = null)
    {
        parent::__construct($name, $id, $displayName, $icon);
        $this->credentials = $credentials;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    public function getCredentials(): array
    {
        return $this->credentials;
    }
}
