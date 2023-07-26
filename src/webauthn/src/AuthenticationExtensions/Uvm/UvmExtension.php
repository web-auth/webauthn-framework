<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions\Uvm;

use Webauthn\AuthenticationExtensions\Extension;
use Webauthn\AuthenticationExtensions\ExtensionInput;
use Webauthn\AuthenticationExtensions\ExtensionOutput;

final class UvmExtension implements Extension
{
    public static function identifier(): string
    {
        return 'uvm';
    }

    public function check(ExtensionInput $input, ?ExtensionOutput $output): void
    {
        // No checks needed
    }

    public static function loadInput(mixed $data): ExtensionInput
    {
        is_bool($data) || throw new \InvalidArgumentException('Invalid input');

        return UvmExtensionInput::create($data);
    }

    public static function loadOutput(mixed $data): ExtensionOutput
    {
        is_array($data) || throw new \InvalidArgumentException('Invalid output');

        return UvmExtensionOutput::create($data);
    }
}
