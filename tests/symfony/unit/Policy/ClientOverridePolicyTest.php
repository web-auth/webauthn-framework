<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Policy;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Policy\ClientOverrideRule;

/**
 * @internal
 */
final class ClientOverridePolicyTest extends TestCase
{
    #[Test]
    public function aFieldWithoutARuleIsNotOverridable(): void
    {
        $policy = ClientOverridePolicy::fromRules();

        static::assertFalse($policy->canOverride('user_verification'));
        static::assertFalse($policy->isValueAllowed('user_verification', 'preferred'));
    }

    #[Test]
    public function fromRulesAcceptsAnyValueWhenTheRuleHasNoAllowList(): void
    {
        $policy = ClientOverridePolicy::fromRules(extensions: ClientOverrideRule::any());

        static::assertTrue($policy->canOverride('extensions'));
        static::assertTrue($policy->isValueAllowed('extensions', [
            'credProps' => true,
        ]));
    }

    #[Test]
    public function fromRulesRestrictsValuesWhenAnAllowListIsProvided(): void
    {
        $policy = ClientOverridePolicy::fromRules(
            userVerification: ClientOverrideRule::restrictTo(['preferred', 'required']),
        );

        static::assertTrue($policy->isValueAllowed('user_verification', 'preferred'));
        static::assertTrue($policy->isValueAllowed('user_verification', 'required'));
        static::assertFalse($policy->isValueAllowed('user_verification', 'discouraged'));
    }

    #[Test]
    public function getEffectiveValueFallsBackToTheProfileWhenTheClientValueIsNull(): void
    {
        $policy = ClientOverridePolicy::fromRules(userVerification: ClientOverrideRule::any());

        static::assertSame('preferred', $policy->getEffectiveValue('user_verification', null, 'preferred'));
    }

    #[Test]
    public function getEffectiveValueFallsBackWhenTheClientSubmitsADisallowedValue(): void
    {
        $policy = ClientOverridePolicy::fromRules(
            userVerification: ClientOverrideRule::restrictTo(['preferred', 'required']),
        );

        static::assertSame(
            'preferred',
            $policy->getEffectiveValue('user_verification', 'discouraged', 'preferred'),
        );
    }

    #[Test]
    public function getEffectiveValueAcceptsTheClientValueWhenItPassesTheAllowList(): void
    {
        $policy = ClientOverridePolicy::fromRules(
            userVerification: ClientOverrideRule::restrictTo(['preferred', 'required']),
        );

        static::assertSame('required', $policy->getEffectiveValue('user_verification', 'required', 'preferred'));
    }

    #[Test]
    public function legacyArrayShapeRemainsAFirstClassConstructorPath(): void
    {
        $policy = new ClientOverridePolicy([
            'user_verification' => [
                'enabled' => true,
                'allowed_values' => ['preferred', 'required'],
            ],
            'extensions' => [
                'enabled' => true,
            ],
        ]);

        static::assertTrue($policy->canOverride('user_verification'));
        static::assertTrue($policy->isValueAllowed('user_verification', 'required'));
        static::assertFalse($policy->isValueAllowed('user_verification', 'discouraged'));

        static::assertTrue($policy->canOverride('extensions'));
        static::assertTrue($policy->isValueAllowed('extensions', 'anything'));
    }

    #[Test]
    public function legacyArrayShapeSkipsFieldsWithEnabledFalse(): void
    {
        $policy = new ClientOverridePolicy([
            'user_verification' => [
                'enabled' => false,
                'allowed_values' => ['preferred', 'required'],
            ],
        ]);

        static::assertFalse($policy->canOverride('user_verification'));
    }

    #[Test]
    public function constructorAcceptsAMixOfTypedAndLegacyEntries(): void
    {
        $policy = new ClientOverridePolicy([
            'user_verification' => ClientOverrideRule::restrictTo(['preferred']),
            'extensions' => [
                'enabled' => true,
            ],
            'mediation' => [
                'enabled' => false,
            ],
        ]);

        static::assertTrue($policy->canOverride('user_verification'));
        static::assertTrue($policy->canOverride('extensions'));
        static::assertFalse($policy->canOverride('mediation'));
    }

    #[Test]
    public function theServerExtensionsAreKeptWhenTheClientSendsAnEmptyObject(): void
    {
        $server = self::serverExtensions();

        $effective = (new ClientOverridePolicy([
            'extensions' => [
                'enabled' => true,
            ],
        ]))->getEffectiveExtensions([], $server);

        static::assertSame(['payment', 'credProps'], array_keys($effective->extensions));
        static::assertSame($server->get('payment')->value, $effective->get('payment')->value);
    }

    #[Test]
    public function theClientCanAddExtensionsButNeitherRemoveNorReplaceTheServerOnes(): void
    {
        $effective = (new ClientOverridePolicy([
            'extensions' => [
                'enabled' => true,
            ],
        ]))->getEffectiveExtensions([
            'payment' => [
                'isPayment' => false,
            ],
            'credProps' => false,
            'uvm' => true,
            0 => 'not an extension identifier',
        ], self::serverExtensions());

        static::assertSame(['payment', 'credProps', 'uvm'], array_keys($effective->extensions));
        static::assertSame([
            'isPayment' => true,
        ], $effective->get('payment')->value);
        static::assertTrue($effective->get('credProps')->value);
        static::assertTrue($effective->get('uvm')->value);
    }

    #[Test]
    public function theServerExtensionsAreKeptWhenTheExtensionsAreNotOverridable(): void
    {
        $server = self::serverExtensions();

        static::assertSame($server, (new ClientOverridePolicy())->getEffectiveExtensions([
            'uvm' => true,
        ], $server));
        static::assertSame($server, (new ClientOverridePolicy([
            'extensions' => [
                'enabled' => true,
            ],
        ]))->getEffectiveExtensions(null, $server));
    }

    private static function serverExtensions(): AuthenticationExtensions
    {
        return AuthenticationExtensions::create([
            AuthenticationExtension::create('payment', [
                'isPayment' => true,
            ]),
            AuthenticationExtension::create('credProps', true),
        ]);
    }
}
