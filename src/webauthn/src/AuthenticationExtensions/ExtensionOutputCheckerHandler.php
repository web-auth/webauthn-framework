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

namespace Webauthn\AuthenticationExtensions;

use JetBrains\PhpStorm\Pure;

class ExtensionOutputCheckerHandler
{
    /**
     * @var ExtensionOutputChecker[]
     */
    private array $checkers = [];

    #[Pure]
    public static function create(): self
    {
        return new self();
    }

    public function add(ExtensionOutputChecker $checker): self
    {
        $this->checkers[] = $checker;

        return $this;
    }

    /**
     * @throws ExtensionOutputError
     */
    public function check(AuthenticationExtensionsClientInputs $inputs, AuthenticationExtensionsClientOutputs $outputs): void
    {
        foreach ($this->checkers as $checker) {
            $checker->check($inputs, $outputs);
        }
    }
}
