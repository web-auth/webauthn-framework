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

namespace Webauthn\Bundle\Security\Handler;

use Symfony\Component\HttpFoundation\Response;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

interface RequestOptionsHandler
{
    public function onRequestOptions(PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, ?PublicKeyCredentialUserEntity $userEntity): Response;
}
