<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Policy;

use function is_array;

/**
 * Decides whether a request body field can override the server-side default
 * for a given WebAuthn options field, and validates that an override value is
 * within the configured allow-list.
 *
 * Two equivalent ways to build a policy:
 *
 *   - Typed factory {@see self::fromRules()} with {@see ClientOverrideRule}
 *     value objects:
 *
 *         $policy = ClientOverridePolicy::fromRules(
 *             userVerification: ClientOverrideRule::restrictTo(['preferred', 'required']),
 *             extensions:       ClientOverrideRule::any(),
 *         );
 *
 *   - Legacy nested-array form via {@see self::__construct()} (the shape used
 *     by the bundle's deprecated `client_override_policy` YAML node):
 *
 *         $policy = new ClientOverridePolicy([
 *             'user_verification' => [
 *                 'enabled' => true,
 *                 'allowed_values' => ['preferred', 'required'],
 *             ],
 *             'extensions' => ['enabled' => true],
 *         ]);
 *
 * Both shapes are supported as first-class APIs; the constructor accepts
 * either typed {@see ClientOverrideRule} entries or the legacy
 * `{enabled, allowed_values?}` shape, on a per-field basis.
 *
 * Six fields are queryable through {@see self::canOverride()},
 * {@see self::isValueAllowed()} and {@see self::getEffectiveValue()}:
 *
 *   - `user_verification`
 *   - `authenticator_attachment`
 *   - `resident_key`
 *   - `attestation_conveyance`
 *   - `extensions`
 *   - `mediation`
 */
final readonly class ClientOverridePolicy
{
    /**
     * @var array<string, ClientOverrideRule>
     */
    private array $rules;

    /**
     * @param array<string, ClientOverrideRule>|array<string, array{enabled: bool, allowed_values?: list<string>}> $policies
     *        Each entry can be either a {@see ClientOverrideRule} value object
     *        or a `{enabled: bool, allowed_values?: list<string>}` array. The
     *        two shapes can be mixed within the same call.
     */
    public function __construct(array $policies = [])
    {
        $rules = [];
        foreach ($policies as $field => $entry) {
            if ($entry instanceof ClientOverrideRule) {
                $rules[$field] = $entry;
                continue;
            }
            if (is_array($entry) && ($entry['enabled'] ?? false) === true) {
                $rules[$field] = new ClientOverrideRule($entry['allowed_values'] ?? null);
            }
        }

        $this->rules = $rules;
    }

    /**
     * Build a policy from typed {@see ClientOverrideRule} value objects, one
     * per overridable field. Pass `null` (the default) for fields the client
     * must NOT be able to override.
     */
    public static function fromRules(
        ?ClientOverrideRule $userVerification = null,
        ?ClientOverrideRule $authenticatorAttachment = null,
        ?ClientOverrideRule $residentKey = null,
        ?ClientOverrideRule $attestationConveyance = null,
        ?ClientOverrideRule $extensions = null,
        ?ClientOverrideRule $mediation = null,
    ): self {
        $rules = array_filter([
            'user_verification' => $userVerification,
            'authenticator_attachment' => $authenticatorAttachment,
            'resident_key' => $residentKey,
            'attestation_conveyance' => $attestationConveyance,
            'extensions' => $extensions,
            'mediation' => $mediation,
        ], static fn (?ClientOverrideRule $rule): bool => $rule !== null);

        return new self($rules);
    }

    public function canOverride(string $field): bool
    {
        return isset($this->rules[$field]);
    }

    public function isValueAllowed(string $field, mixed $value): bool
    {
        $rule = $this->rules[$field] ?? null;

        return $rule !== null && $rule->isValueAllowed($value);
    }

    /**
     * Resolve the value to use for the given field: returns `$requestValue` if
     * the field is overridable AND the value passes the allow-list, otherwise
     * falls back to `$profileValue`.
     */
    public function getEffectiveValue(string $field, mixed $requestValue, mixed $profileValue): mixed
    {
        if ($requestValue === null) {
            return $profileValue;
        }

        if (! $this->isValueAllowed($field, $requestValue)) {
            return $profileValue;
        }

        return $requestValue;
    }
}
