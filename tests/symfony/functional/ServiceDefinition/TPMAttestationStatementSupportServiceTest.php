<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\ServiceDefinition;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractExtensionTestCase;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;

/**
 * Some TPMs sign their attestation statement with RS1 (RSASSA-PKCS1-v1_5 with SHA-1), which cose-lib verifies without
 * a warning only when the algorithm is acknowledged. The TPM attestation statement support acknowledges it only when
 * the application enables "metadata.tpm_acknowledge_insecure_algorithm".
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/999
 * @internal
 */
final class TPMAttestationStatementSupportServiceTest extends AbstractExtensionTestCase
{
    #[Test]
    public function theInsecureAlgorithmIsNotAcknowledgedByDefault(): void
    {
        $this->load([
            'clock' => 'system',
            'metadata' => [
                'enabled' => true,
                'mds_repository' => 'app.metadata_statement_repository',
                'status_report_repository' => 'app.status_report_repository',
            ],
        ]);

        $this->assertContainerBuilderHasServiceDefinitionWithArgument(
            TPMAttestationStatementSupport::class,
            1,
            '%webauthn.metadata.tpm_acknowledge_insecure_algorithm%'
        );
        $this->assertContainerBuilderHasParameter('webauthn.metadata.tpm_acknowledge_insecure_algorithm', false);
    }

    #[Test]
    public function theApplicationCanAcknowledgeTheInsecureAlgorithm(): void
    {
        $this->load([
            'clock' => 'system',
            'metadata' => [
                'enabled' => true,
                'mds_repository' => 'app.metadata_statement_repository',
                'status_report_repository' => 'app.status_report_repository',
                'tpm_acknowledge_insecure_algorithm' => true,
            ],
        ]);

        $this->assertContainerBuilderHasServiceDefinitionWithArgument(
            TPMAttestationStatementSupport::class,
            1,
            '%webauthn.metadata.tpm_acknowledge_insecure_algorithm%'
        );
        $this->assertContainerBuilderHasParameter('webauthn.metadata.tpm_acknowledge_insecure_algorithm', true);
    }

    protected function getContainerExtensions(): array
    {
        return [new WebauthnExtension('webauthn')];
    }
}
