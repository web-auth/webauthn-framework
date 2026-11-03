<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Configuration;

use PHPUnit\Framework\Attributes\Test;
use ReflectionObject;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CheckAllowedOrigins;
use Webauthn\Tests\Bundle\Functional\WebauthnTestCase;

/**
 * Regression test that pins the per-controller origin override behaviour for
 * `controllers.creation[].allowed_origins` / `allow_subdomains` and the
 * deprecated `secured_rp_ids` alias on both `creation` and `request` controllers.
 *
 * Prior to this fix, the bundle accepted these fields in the YAML schema but
 * silently dropped them at runtime: `WebauthnExtension` passed
 * `secured_rp_ids` as the first positional argument to
 * `CeremonyStepManagerFactory::creationCeremony()` / `requestCeremony()`, but
 * those methods had stopped accepting arguments after commit 1dc03432
 * ("Major upgrade", July 2024). PHP silently dropped the extra positional
 * argument and the per-controller CSM kept inheriting the global
 * `webauthn.allowed_origins` only. `controllers[].allowed_origins` itself was
 * never even read by the extension.
 *
 * This test boots the actual test kernel and inspects the per-controller
 * `CheckAllowedOrigins` step to confirm:
 *
 *   - the per-controller `allowed_origins` list is honoured (overrides root),
 *   - `allow_subdomains` is honoured per-controller too, and
 *   - the override is properly scoped to the controller (the global value
 *     is unaffected).
 *
 * The test kernel's root `webauthn.allowed_origins` lists 5 entries, but
 * `controllers.creation.test.allowed_origins` is a single distinctive value
 * (`https://creation-test.example`) and likewise for the request controller.
 *
 * @internal
 */
final class ControllersConfigOriginOverrideTest extends WebauthnTestCase
{
    #[Test]
    public function creationControllerHonoursItsOwnAllowedOriginsAndAllowSubdomains(): void
    {
        self::bootKernel();

        $csm = static::getContainer()
            ->get('webauthn.controller.creation.response.ceremony_step_manager.test');
        static::assertInstanceOf(CeremonyStepManager::class, $csm);

        $check = $this->extractCheckAllowedOrigins($csm);

        static::assertSame(
            ['https://creation-test.example'],
            $this->reflectProperty($check, 'fullOrigins'),
            'Per-controller `controllers.creation[].allowed_origins` MUST override the global list.'
        );
        static::assertTrue(
            $this->reflectProperty($check, 'allowSubdomains'),
            'Per-controller `controllers.creation[].allow_subdomains` MUST be honoured.'
        );
    }

    #[Test]
    public function requestControllerHonoursItsOwnAllowedOriginsAndAllowSubdomains(): void
    {
        self::bootKernel();

        $csm = static::getContainer()
            ->get('webauthn.controller.request.response.ceremony_step_manager.test');
        static::assertInstanceOf(CeremonyStepManager::class, $csm);

        $check = $this->extractCheckAllowedOrigins($csm);

        static::assertSame(
            ['https://request-test.example'],
            $this->reflectProperty($check, 'fullOrigins'),
            'Per-controller `controllers.request[].allowed_origins` MUST override the global list.'
        );
        static::assertFalse(
            $this->reflectProperty($check, 'allowSubdomains'),
            'Per-controller `controllers.request[].allow_subdomains` MUST be honoured.'
        );
    }

    #[Test]
    public function rootAllowedOriginsRemainsUnchangedByPerControllerOverrides(): void
    {
        self::bootKernel();

        // The bundle exposes the root list as a parameter; if a per-controller
        // override leaked into the global state, this would shrink to a single
        // entry. It must keep the full list.
        static::assertSame(
            [
                'https://localhost',
                'https://localhost:8443',
                'https://bar.acme',
                'https://webauthn.spomky-labs.com',
                'https://spomky-webauthn.herokuapp.com',
            ],
            static::getContainer()->getParameter('webauthn.allowed_origins'),
            'Per-controller overrides MUST NOT mutate the global `webauthn.allowed_origins`.'
        );
    }

    private function extractCheckAllowedOrigins(CeremonyStepManager $csm): CheckAllowedOrigins
    {
        $steps = $this->reflectProperty($csm, 'steps');
        static::assertIsArray($steps);

        foreach ($steps as $step) {
            if ($step instanceof CheckAllowedOrigins) {
                return $step;
            }
        }

        static::fail('Expected a CheckAllowedOrigins step in the ceremony step manager.');
    }

    private function reflectProperty(object $target, string $name): mixed
    {
        return (new ReflectionObject($target))
            ->getProperty($name)
            ->getValue($target);
    }
}
