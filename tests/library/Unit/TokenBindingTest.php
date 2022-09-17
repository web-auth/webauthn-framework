<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;
use Webauthn\TokenBinding\TokenBinding;

/**
 * @internal
 */
final class TokenBindingTest extends TestCase
{
    /**
     * @test
     */
    public function aTokenBindingCanBeCreatedAndValueAccessed(): void
    {
        $tokenBinding = new TokenBinding('present', 'id');

        static::assertSame('present', $tokenBinding->getStatus());
        static::assertSame('id', $tokenBinding->getId());
    }

    /**
     * @test
     */
    public function anIDIsRequiredWhenStatusIsPresent(): never
    {
        //Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('The member "id" is required when status is "present"');

        //When
        new TokenBinding('present', null);
    }

    /**
     * @test
     * @dataProvider dataCreationFromArray
     */
    public function aTokenBindingCanBeCreatedFromArrayObject(
        array $data,
        ?array $exception,
        ?string $expectedStatus,
        ?string $expectedId
    ): void {
        if ($exception !== null) {
            static::expectException($exception['class']);
            static::expectExceptionMessage($exception['message']);
        }

        $tokenBinding = TokenBinding::createFormArray($data);

        static::assertSame($expectedStatus, $tokenBinding->getStatus());
        static::assertSame($expectedId, $tokenBinding->getId());
    }

    public function dataCreationFromArray(): array
    {
        return [
            [
                'data' => [
                    'status' => TokenBinding::TOKEN_BINDING_STATUS_NOT_SUPPORTED,
                ],
                'exception' => null,
                'expectedStatus' => TokenBinding::TOKEN_BINDING_STATUS_NOT_SUPPORTED,
                'expectedId' => null,
            ],
            [
                'data' => [
                    'status' => TokenBinding::TOKEN_BINDING_STATUS_SUPPORTED,
                ],
                'exception' => null,
                'expectedStatus' => TokenBinding::TOKEN_BINDING_STATUS_SUPPORTED,
                'expectedId' => null,
            ],
            [
                'data' => [
                    'status' => TokenBinding::TOKEN_BINDING_STATUS_PRESENT,
                ],
                'exception' => [
                    'class' => InvalidArgumentException::class,
                    'message' => 'The member "id" is required when status is "present"',
                ],
                'expectedStatus' => null,
                'expectedId' => null,
            ],
            [
                'data' => [],
                'exception' => [
                    'class' => InvalidArgumentException::class,
                    'message' => 'The member "status" is required',
                ],
                'expectedStatus' => null,
                'expectedId' => null,
            ],
            [
                'data' => [
                    'status' => TokenBinding::TOKEN_BINDING_STATUS_PRESENT,
                ],
                'exception' => [
                    'class' => InvalidArgumentException::class,
                    'message' => 'The member "id" is required when status is "present"',
                ],
                'expectedStatus' => null,
                'expectedId' => null,
            ],
            [
                'data' => [
                    'status' => TokenBinding::TOKEN_BINDING_STATUS_PRESENT,
                    'id' => Base64UrlSafe::encodeUnpadded('id'),
                ],
                'exception' => null,
                'expectedStatus' => TokenBinding::TOKEN_BINDING_STATUS_PRESENT,
                'expectedId' => 'id',
            ],
        ];
    }
}
