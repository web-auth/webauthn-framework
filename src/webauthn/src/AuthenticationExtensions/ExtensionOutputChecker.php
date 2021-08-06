<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

interface ExtensionOutputChecker
{
    /**
     * @throws ExtensionOutputError
     */
    public function check(AuthenticationExtensionsClientInputs $inputs, AuthenticationExtensionsClientOutputs $outputs): void;
}
