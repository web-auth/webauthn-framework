<?php

declare(strict_types=1);

namespace Cose\Tests\Unit\Manager;

use Cose\Tests\Unit\CoseTestCase;
use function count;
use InvalidArgumentException;

/**
 * @internal
 */
final class ManagerAndFactoryTest extends CoseTestCase
{
    /**
     * @test
     * @dataProvider getAliases
     */
    public function aManagerCanBeGeneratedUsingAliases(string ...$aliases): void
    {
        $manager = $this->getFactory()
            ->generate(...$aliases)
        ;

        static::assertCount(count($aliases), $manager->list());
    }

    /**
     * @test
     */
    public function aManagerCannotBeGeneratedWhenAnAliasIsMissing(): void
    {
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('The algorithm with alias "FOO" is not supported');
        $this->getFactory()
            ->generate('FOO')
        ;
    }

    /**
     * @return array<string>[]
     */
    public function getAliases(): array
    {
        return [['HS256', 'RS256'], ['HS512', 'RS384', 'HS256']];
    }
}
