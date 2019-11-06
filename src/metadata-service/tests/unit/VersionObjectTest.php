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

namespace Webauthn\MetadataService\Tests\Unit;

use LogicException;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Version;

/**
 * @group unit
 * @group Fido2
 */
class VersionObjectTest extends TestCase
{
    /**
     * @test
     * @dataProvider validObjectData
     */
    public function validObject(Version $object, ?int $major, ?int $minor, string $expectedJson): void
    {
        static::assertEquals($major, $object->getMajor());
        static::assertEquals($minor, $object->getMinor());
        static::assertEquals($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));

        $loaded = Version::createFromArray(json_decode($expectedJson, true));
        static::assertEquals($object, $loaded);
    }

    public function validObjectData(): array
    {
        return [
            [new Version(1, null), 1, null, '{"major":1}'],
            [new Version(null, 50), null, 50, '{"minor":50}'],
            [new Version(1, 50), 1, 50, '{"major":1,"minor":50}'],
        ];
    }

    /**
     * @test
     * @dataProvider invalidObjectData
     */
    public function invalidObject(?int $major, ?int $minor, string $expectedMessage): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage($expectedMessage);

        new Version($major, $minor);
    }

    public function invalidObjectData(): array
    {
        return [
            [null, null, 'Invalid data. Must contain at least one item'],
        ];
    }
}
