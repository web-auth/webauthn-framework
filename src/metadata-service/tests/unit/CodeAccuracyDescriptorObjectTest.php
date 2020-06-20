<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\MetadataService\Tests\Unit;

use LogicException;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\CodeAccuracyDescriptor;

/**
 * @group unit
 * @group Fido2
 * @group FOO
 *
 * @internal
 */
class CodeAccuracyDescriptorObjectTest extends TestCase
{
    /**
     * @test
     * @dataProvider validObjectData
     */
    public function validObject(CodeAccuracyDescriptor $object, int $base, int $minLength, ?int $maxRetries, ?int $blockSlowdown, string $expectedJson): void
    {
        static::assertEquals($base, $object->getBase());
        static::assertEquals($minLength, $object->getMinLength());
        static::assertEquals($maxRetries, $object->getMaxRetries());
        static::assertEquals($blockSlowdown, $object->getBlockSlowdown());
        static::assertEquals($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));

        $loaded = CodeAccuracyDescriptor::createFromArray(json_decode($expectedJson, true));
        static::assertEquals($object, $loaded);
    }

    public function validObjectData(): array
    {
        return [
            [new CodeAccuracyDescriptor(10, 4), 10, 4, null, null, '{"base":10,"minLength":4}'],
            [new CodeAccuracyDescriptor(10, 4, 50, 15), 10, 4, 50, 15, '{"base":10,"minLength":4,"maxRetries":50,"blockSlowdown":15}'],
        ];
    }

    /**
     * @test
     * @dataProvider invalidObjectData
     */
    public function invalidObject(int $base, int $minLength, ?int $maxRetries, ?int $blockSlowdown, string $expectedMessage): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage($expectedMessage);

        new CodeAccuracyDescriptor($base, $minLength, $maxRetries, $blockSlowdown);
    }

    public function invalidObjectData(): array
    {
        return [
            [-1, -1, null, null, 'Invalid data. The value of "base" must be a positive integer'],
            [11, -1, -1, null, 'Invalid data. The value of "minLength" must be a positive integer'],
            [11, 1, -1, -1, 'Invalid data. The value of "maxRetries" must be a positive integer'],
            [11, 1, 1, -1, 'Invalid data. The value of "blockSlowdown" must be a positive integer'],
        ];
    }
}
