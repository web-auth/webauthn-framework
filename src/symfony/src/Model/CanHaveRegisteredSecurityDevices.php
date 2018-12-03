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

namespace Webauthn\Bundle\Model;

use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\PublicKeyCredentialDescriptor;

interface CanHaveRegisteredSecurityDevices extends UserInterface
{
    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    public function getSecurityDeviceCredentialIds(): iterable;
}
