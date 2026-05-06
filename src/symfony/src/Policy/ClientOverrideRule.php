<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Policy;

use function in_array;

/**
 * Per-field rule used by {@see ClientOverridePolicy}: marks a field as
 * client-overridable and optionally restricts the values the client can submit.
 *
 * Presence of a rule on the policy means the field is overridable. Absence of a
 * rule means the server alone decides the value.
 *
 *   new ClientOverrideRule()                                  // any value accepted
 *   new ClientOverrideRule(['preferred', 'required'])         // restrict to a list
 *   ClientOverrideRule::any()                                 // alias of ::__construct()
 *   ClientOverrideRule::restrictTo(['preferred', 'required']) // alias of the restriction form
 */
final readonly class ClientOverrideRule
{
    /**
     * @param null|list<string> $allowedValues Pass `null` to accept any value;
     *                                         pass an explicit list to whitelist
     *                                         the acceptable client values.
     */
    public function __construct(
        public ?array $allowedValues = null,
    ) {
    }

    public static function any(): self
    {
        return new self();
    }

    /**
     * @param list<string> $allowedValues
     */
    public static function restrictTo(array $allowedValues): self
    {
        return new self($allowedValues);
    }

    public function isValueAllowed(mixed $value): bool
    {
        return $this->allowedValues === null || in_array($value, $this->allowedValues, true);
    }
}
