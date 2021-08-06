<?php

declare(strict_types=1);

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
