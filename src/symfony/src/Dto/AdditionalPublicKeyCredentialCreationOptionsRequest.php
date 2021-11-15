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

namespace Webauthn\Bundle\Dto;

use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\Type;
use Webauthn\PublicKeyCredentialCreationOptions;

final class AdditionalPublicKeyCredentialCreationOptionsRequest
{
    public ?array $authenticatorSelection = null;

    #[Type(type: 'string')]
    #[Choice(choices: [
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
    ])]
    public string $attestation;

    public ?array $extensions = null;
}
