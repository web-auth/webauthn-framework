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
use Prophecy\PhpUnit\ProphecyTrait;
use function Safe\json_decode;
use function Safe\json_encode;
use Webauthn\MetadataService\PatternAccuracyDescriptor;

/**
 * @group unit
 * @group Fido2
 *
 * @internal
 */
class PatternAccuracyDescriptorObjectTest extends TestCase
{
    use ProphecyTrait;

    /**
     * @test
     * @dataProvider validObjectData
     */
    public function validObject(PatternAccuracyDescriptor $object, int $minComplexity, ?int $maxRetries, ?int $blockSlowdown, string $expectedJson): void
    {
        static::assertEquals($minComplexity, $object->getMinComplexity());
        static::assertEquals($maxRetries, $object->getMaxRetries());
        static::assertEquals($blockSlowdown, $object->getBlockSlowdown());
        static::assertEquals($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));

        $loaded = PatternAccuracyDescriptor::createFromArray(json_decode($expectedJson, true));
        static::assertEquals($object, $loaded);
    }

    public function validObjectData(): array
    {
        return [
            [new PatternAccuracyDescriptor(10), 10, null, null, '{"minComplexity":10}'],
            [new PatternAccuracyDescriptor(10, 50, 15), 10, 50, 15, '{"minComplexity":10,"maxRetries":50,"blockSlowdown":15}'],
        ];
    }

    /**
     * @test
     * @dataProvider invalidObjectData
     */
    public function invalidObject(int $minComplexity, ?int $maxRetries, ?int $blockSlowdown, string $expectedMessage): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage($expectedMessage);

        new PatternAccuracyDescriptor($minComplexity, $maxRetries, $blockSlowdown);
    }

    public function invalidObjectData(): array
    {
        return [
            [-1, null, null, 'Invalid data. The value of "minComplexity" must be a positive integer'],
            [11, -1, null, 'Invalid data. The value of "maxRetries" must be a positive integer'],
            [11, 1, -1, 'Invalid data. The value of "blockSlowdown" must be a positive integer'],
        ];
    }
}
