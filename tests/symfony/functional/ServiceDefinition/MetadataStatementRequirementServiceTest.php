<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\ServiceDefinition;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractExtensionTestCase;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;

/**
 * A full attestation whose AAGUID has no Metadata Statement is refused unless the application sets
 * "metadata.require_statement" to false.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1002
 * @internal
 */
final class MetadataStatementRequirementServiceTest extends AbstractExtensionTestCase
{
    #[Test]
    public function aStatementIsRequiredByDefault(): void
    {
        $this->load([
            'clock' => 'system',
            'metadata' => [
                'enabled' => true,
                'mds_repository' => 'app.metadata_statement_repository',
                'status_report_repository' => 'app.status_report_repository',
            ],
        ]);

        $this->assertContainerBuilderHasParameter('webauthn.metadata.require_statement', true);
    }

    #[Test]
    public function theApplicationCanAcceptTheAuthenticatorsTheMetadataDoNotKnow(): void
    {
        $this->load([
            'clock' => 'system',
            'metadata' => [
                'enabled' => true,
                'mds_repository' => 'app.metadata_statement_repository',
                'status_report_repository' => 'app.status_report_repository',
                'require_statement' => false,
            ],
        ]);

        $this->assertContainerBuilderHasParameter('webauthn.metadata.require_statement', false);
    }

    protected function getContainerExtensions(): array
    {
        return [new WebauthnExtension('webauthn')];
    }
}
