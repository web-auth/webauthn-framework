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

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;

interface CreationSuccessHandler
{
    public function onCreationSuccess(Request $request, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, AuthenticatorAttestationResponse $authenticatorAttestationResponse, PublicKeyCredentialSource $publicKeyCredentialSource): Response;
}
