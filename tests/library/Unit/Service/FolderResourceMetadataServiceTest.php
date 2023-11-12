<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\Service;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;
use Webauthn\MetadataService\Service\FolderResourceMetadataService;

/**
 * @internal
 */
final class FolderResourceMetadataServiceTest extends TestCase
{
    #[Test]
    public function theListIsCorrect(): void
    {
        // Given
        $service = FolderResourceMetadataService::create(__DIR__ . '/../../mds////');

        // When
        $list = [...$service->list()];

        // Then
        static::assertContains('9debdbfd-14dd-4e8d-877b-000000000000', $list);
        static::assertContains('9debdbfd-14dd-4e8d-877b-4a6e35ddb375', $list);
        static::assertContains('91dfead7-959e-4475-ad26-9b0d482be089', $list);
        static::assertContains('a8d59924-63b7-49ea-b9de-34a753de1e01', $list);
    }

    #[Test]
    public function theAAGUIDIsSupported(): void
    {
        // Given
        $service = FolderResourceMetadataService::create(__DIR__ . '/../../mds');

        // When
        $isValid = $service->has('9debdbfd-14dd-4e8d-877b-000000000000');

        // Then
        static::assertTrue($isValid);
    }

    #[Test]
    public function theMetadataStatementIsRead(): void
    {
        // Given
        $service = FolderResourceMetadataService::create(__DIR__ . '/../../mds');

        // When
        $mds = $service->get('9debdbfd-14dd-4e8d-877b-4a6e35ddb375');

        // Then
        static::assertSame('9debdbfd-14dd-4e8d-877b-4a6e35ddb375', $mds->aaguid);
    }

    #[Test]
    public function theMetadataStatementIsInvalid(): void
    {
        // Then
        static::expectException(Throwable::class);
        static::expectExceptionMessage('Syntax error');

        // Given
        $service = FolderResourceMetadataService::create(__DIR__ . '/../../mds');

        // When
        $service->get('9debdbfd-14dd-4e8d-877b-000000000000');
    }
}
