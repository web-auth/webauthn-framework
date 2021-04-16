<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use JetBrains\PhpStorm\Pure;
use function Safe\base64_decode;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
 */
class AuthenticatorAssertionResponse extends AuthenticatorResponse
{
    #[Pure]
    public function __construct(CollectedClientData $clientDataJSON, private AuthenticatorData $authenticatorData, private string $signature, private ?string $userHandle)
    {
        parent::__construct($clientDataJSON);
    }

    #[Pure]
    public function getAuthenticatorData(): AuthenticatorData
    {
        return $this->authenticatorData;
    }

    #[Pure]
    public function getSignature(): string
    {
        return $this->signature;
    }

    public function getUserHandle(): ?string
    {
        if (null === $this->userHandle || '' === $this->userHandle) {
            return $this->userHandle;
        }

        return base64_decode($this->userHandle, true);
    }
}
