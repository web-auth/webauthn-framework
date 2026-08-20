<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\PasskeyEndpointsResponse;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\Url;

/**
 * @internal
 */
final class PasskeyEndpointsResponseTest extends AbstractTestCase
{
    #[Test]
    public function createEmptyResponseReturnsEmptyJsonObject(): void
    {
        // Given
        $response = PasskeyEndpointsResponse::createEmpty();

        // When
        $json = $this->getSerializer()
            ->serialize($response, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then - empty array is normalized to []
        static::assertSame('[]', $json);
    }

    #[Test]
    public function createResponseWithAllFieldsReturnsCompleteJsonObject(): void
    {
        // Given
        $response = PasskeyEndpointsResponse::create(
            enroll: Url::create('https://example.com/enroll'),
            manage: Url::create('https://example.com/manage'),
            prfUsageDetails: Url::create('https://example.com/prf-info')
        );

        // When
        $json = $this->getSerializer()
            ->serialize($response, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertJsonStringEqualsJsonString(
            '{"enroll":"https://example.com/enroll","manage":"https://example.com/manage","prfUsageDetails":"https://example.com/prf-info"}',
            $json
        );
    }

    #[Test]
    public function createResponseWithSomeFieldsOmitsNullValues(): void
    {
        // Given
        $response = PasskeyEndpointsResponse::create(
            enroll: Url::create('https://example.com/enroll'),
            prfUsageDetails: Url::create('https://example.com/prf-info')
        );

        // When
        $json = $this->getSerializer()
            ->serialize($response, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertJsonStringEqualsJsonString(
            '{"enroll":"https://example.com/enroll","prfUsageDetails":"https://example.com/prf-info"}',
            $json
        );
    }

    #[Test]
    public function serializeCorrectlyHandlesNullValues(): void
    {
        // Given
        $response = new PasskeyEndpointsResponse(
            enroll: Url::create('https://example.com/enroll'),
            manage: Url::create('https://example.com/manage')
        );

        // When
        $json = $this->getSerializer()
            ->serialize($response, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertJsonStringEqualsJsonString(
            '{"enroll":"https://example.com/enroll","manage":"https://example.com/manage"}',
            $json
        );
    }
}
