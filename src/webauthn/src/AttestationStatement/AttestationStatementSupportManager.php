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

namespace Webauthn\AttestationStatement;

use function array_key_exists;
use Assert\Assertion;
use JetBrains\PhpStorm\Pure;
use function Safe\sprintf;

class AttestationStatementSupportManager
{
    /**
     * @var AttestationStatementSupport[]
     */
    private array $attestationStatementSupports = [];

    public function add(AttestationStatementSupport $attestationStatementSupport): self
    {
        $this->attestationStatementSupports[$attestationStatementSupport->name()] = $attestationStatementSupport;

        return $this;
    }

    #[Pure]
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->attestationStatementSupports);
    }

    public function get(string $name): AttestationStatementSupport
    {
        Assertion::true($this->has($name), sprintf('The attestation statement format "%s" is not supported.', $name));

        return $this->attestationStatementSupports[$name];
    }
}
