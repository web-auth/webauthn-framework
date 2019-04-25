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

namespace Webauthn\Bundle\Dto;

use Symfony\Component\Validator\Constraints as Assert;

final class ServerPublicKeyCredentialRequestOptionsRequest
{
    /**
     * @var string
     *
     * @Assert\Type("string")
     * @Assert\NotBlank
     */
    public $username;
}
