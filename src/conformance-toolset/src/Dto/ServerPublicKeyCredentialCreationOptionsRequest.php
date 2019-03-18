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

namespace Webauthn\ConformanceToolset\Dto;

use Symfony\Component\Validator\Constraints as Assert;
use Webauthn\PublicKeyCredentialCreationOptions;

final class ServerPublicKeyCredentialCreationOptionsRequest
{
    /**
     * @var string
     *
     * @Assert\Type("string")
     * @Assert\NotBlank
     */
    public $username;

    /**
     * @var string
     *
     * @Assert\Type("string")
     * @Assert\NotBlank
     */
    public $displayName;

    /**
     * @var array|null
     */
    public $authenticatorSelection;

    /**
     * @var string
     *
     * @Assert\Type("string")
     * @Assert\Choice({PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE, PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT, PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT})
     */
    public $attestation;
}
