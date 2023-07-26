<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions\DevicePublicKey;

use Webauthn\AuthenticationExtensions\Extension;
use Webauthn\AuthenticationExtensions\ExtensionInput;
use Webauthn\AuthenticationExtensions\ExtensionOutput;

final class DevicePublicKeyExtension implements Extension
{
    public static function identifier(): string
    {
        return 'devicePubKey';
    }

    public function check(ExtensionInput $input, ?ExtensionOutput $output): void
    {
        // No checks needed
    }

    public static function loadInput(mixed $data): ExtensionInput
    {
        // TODO: Implement loadInput() method.
    }

    public static function loadOutput(mixed $data): ExtensionOutput
    {
        // TODO: Implement loadOutput() method.
    }
}
