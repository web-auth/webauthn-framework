<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Unit;

use Base64Url\Base64Url;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Webauthn\TokenBinding\TokenBinding;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\TokenBinding\TokenBinding
 */
class TokenBindingTest extends TestCase
{
    /**
     * @test
     */
    public function aTokenBindingCanBeCreatedAndValueAccessed(): void
    {
        $tokenBinding = new TokenBinding('status', 'id');

        static::assertEquals('status', $tokenBinding->getStatus());
        static::assertEquals('id', $tokenBinding->getId());
    }

    /**
     * @test
     * @dataProvider dataCreationFromArray
     */
    public function aTokenBindingCanBeCreatedFromArrayObject(array $data, ?array $exception, ?string $expectedStatus, ?string $expectedId): void
    {
        if (null !== $exception) {
            static::expectException($exception['class']);
            static::expectExceptionMessage($exception['message']);
        }

        $tokenBinding = TokenBinding::createFormArray($data);

        static::assertEquals($expectedStatus, $tokenBinding->getStatus());
        static::assertEquals($expectedId, $tokenBinding->getId());
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
                'data' => [
                ],
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
                    'id' => Base64Url::encode('id'),
                ],
                'exception' => null,
                'expectedStatus' => TokenBinding::TOKEN_BINDING_STATUS_PRESENT,
                'expectedId' => 'id',
            ],
        ];
    }
}
