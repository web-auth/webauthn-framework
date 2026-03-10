<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Policy;

use function in_array;

/**
 * Manages client override policies for WebAuthn profile configurations.
 *
 * Determines whether client request values can override profile defaults
 * and validates that override values are within allowed constraints.
 */
final readonly class ClientOverridePolicy
{
    /**
     * @param array<string, array{enabled: bool, allowed_values?: string[]}> $policies
     */
    public function __construct(
        private array $policies = []
    ) {
    }

    /**
     * Check if a field can be overridden by client request.
     */
    public function canOverride(string $field): bool
    {
        return $this->policies[$field]['enabled'] ?? false;
    }

    /**
     * Check if a specific value is allowed for override.
     */
    public function isValueAllowed(string $field, mixed $value): bool
    {
        if (! $this->canOverride($field)) {
            return false;
        }

        $allowedValues = $this->policies[$field]['allowed_values'] ?? null;

        // If no allowed_values specified, all values are allowed
        if ($allowedValues === null) {
            return true;
        }

        return in_array($value, $allowedValues, true);
    }

    /**
     * Get the effective value for a field, considering override policy.
     *
     * @param mixed $requestValue Value from client request
     * @param mixed $profileValue Value from profile configuration
     * @return mixed The value to use
     */
    public function getEffectiveValue(string $field, mixed $requestValue, mixed $profileValue): mixed
    {
        // If no request value provided, always use profile
        if ($requestValue === null) {
            return $profileValue;
        }

        // If override not allowed or value not permitted, use profile
        if (! $this->isValueAllowed($field, $requestValue)) {
            return $profileValue;
        }

        // Use request value (override approved)
        return $requestValue;
    }
}
