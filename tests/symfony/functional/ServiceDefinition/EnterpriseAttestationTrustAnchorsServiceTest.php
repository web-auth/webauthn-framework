<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\ServiceDefinition;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractExtensionTestCase;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\Bundle\DependencyInjection\Compiler\CeremonyStepManagerFactoryCompilerPass;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Tests\PackedAttestationFixture;

/**
 * Issue #1003: the trust anchors an organization pins for its enterprise attestations are given to the ceremony step
 * manager factory through "metadata.enterprise_attestation_trust_anchors".
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1003
 * @internal
 */
final class EnterpriseAttestationTrustAnchorsServiceTest extends AbstractExtensionTestCase
{
    #[Test]
    public function noTrustAnchorIsPinnedByDefault(): void
    {
        $this->load([
            'clock' => 'system',
            'metadata' => [
                'enabled' => true,
                'mds_repository' => 'app.metadata_statement_repository',
                'status_report_repository' => 'app.status_report_repository',
            ],
        ]);
        (new CeremonyStepManagerFactoryCompilerPass())->process($this->container);

        $this->assertContainerBuilderHasParameter('webauthn.metadata.enterprise_attestation_trust_anchors', []);
        static::assertFalse(
            $this->container->getDefinition(CeremonyStepManagerFactory::class)
                ->hasMethodCall('setEnterpriseAttestationTrustAnchors')
        );
    }

    #[Test]
    public function thePinnedTrustAnchorsAreGivenToTheCeremonyStepManagerFactory(): void
    {
        $trustAnchors = [
            PackedAttestationFixture::rootCertificate(PackedAttestationFixture::ORGANIZATION),
            base64_encode(
                PackedAttestationFixture::der(
                    PackedAttestationFixture::rootCertificate(PackedAttestationFixture::VENDOR)
                )
            ),
        ];
        $this->load([
            'clock' => 'system',
            'metadata' => [
                'enabled' => true,
                'mds_repository' => 'app.metadata_statement_repository',
                'status_report_repository' => 'app.status_report_repository',
                'enterprise_attestation_trust_anchors' => $trustAnchors,
            ],
        ]);
        (new CeremonyStepManagerFactoryCompilerPass())->process($this->container);

        $this->assertContainerBuilderHasParameter(
            'webauthn.metadata.enterprise_attestation_trust_anchors',
            $trustAnchors
        );
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            CeremonyStepManagerFactory::class,
            'setEnterpriseAttestationTrustAnchors',
            [$trustAnchors]
        );
    }

    #[Test]
    public function noTrustAnchorIsPinnedWithoutTheMetadataSupport(): void
    {
        $this->load([
            'clock' => 'system',
        ]);
        (new CeremonyStepManagerFactoryCompilerPass())->process($this->container);

        static::assertFalse($this->container->hasParameter('webauthn.metadata.enterprise_attestation_trust_anchors'));
        static::assertFalse(
            $this->container->getDefinition(CeremonyStepManagerFactory::class)
                ->hasMethodCall('setEnterpriseAttestationTrustAnchors')
        );
    }

    protected function getContainerExtensions(): array
    {
        return [new WebauthnExtension('webauthn')];
    }
}
