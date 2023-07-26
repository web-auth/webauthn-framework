<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

interface Extension
{
    public static function identifier(): string;

    /**
     * @param mixed $data
     */
    public static function loadInput(mixed $data): ExtensionInput;

    /**
     * @param mixed $data
     */
    public static function loadOutput(mixed $data): ExtensionOutput;

    public function check(ExtensionInput $input, ?ExtensionOutput $output): void;
}
