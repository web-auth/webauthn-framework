<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

class ExtensionOutputCheckerHandler
{
    /**
     * @var ExtensionOutputChecker[]
     */
    private array $checkers = [];

    public function add(ExtensionOutputChecker $checker): void
    {
        $this->checkers[] = $checker;
    }

    public function check(
        AuthenticationExtensionsClientInputs $inputs,
        AuthenticationExtensionsClientOutputs $outputs
    ): void {
        foreach ($this->checkers as $checker) {
            $checker->check($inputs, $outputs);
        }
    }
}
