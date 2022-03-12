<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use function array_key_exists;
use Assert\Assertion;
use function Safe\sprintf;

class AttestationStatementSupportManager
{
    /**
     * @var AttestationStatementSupport[]
     */
    private array $attestationStatementSupports = [];

    
    public static function create(): self
    {
        return new self();
    }

    public function add(AttestationStatementSupport $attestationStatementSupport): self
    {
        $this->attestationStatementSupports[$attestationStatementSupport->name()] = $attestationStatementSupport;

        return $this;
    }

    
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
