<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\DeadCode\Rector\ClassMethod\RemoveUnusedPrivateMethodParameterRector;
use Rector\Doctrine\Set\DoctrineSetList;
use Rector\Php84\Rector\Param\ExplicitNullableParamTypeRector;
use Rector\PHPUnit\CodeQuality\Rector\Class_\PreferPHPUnitThisCallRector;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\SetList;
use Rector\Symfony\Set\SymfonySetList;
use Rector\ValueObject\PhpVersion;

return static function (RectorConfig $config): void {
    $config->import(SetList::DEAD_CODE);
    $config->import(SymfonySetList::SYMFONY_64);
    $config->import(SymfonySetList::SYMFONY_50_TYPES);
    $config->import(SymfonySetList::SYMFONY_CODE_QUALITY);
    $config->import(SymfonySetList::SYMFONY_CONSTRUCTOR_INJECTION);
    $config->import(DoctrineSetList::DOCTRINE_CODE_QUALITY);
    $config->import(DoctrineSetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->import(PHPUnitSetList::PHPUNIT_CODE_QUALITY);
    $config->import(PHPUnitSetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->import(PHPUnitSetList::PHPUNIT_110);
    $config->paths(
        [__DIR__ . '/src', __DIR__ . '/tests', __DIR__ . '/ecs.php', __DIR__ . '/rector.php', __DIR__ . '/castor.php']
    );
    $config->skip([
        __DIR__ . '/src/symfony/src/DependencyInjection/Configuration.php',
        __DIR__ . '/src/symfony/src/Routing/Loader.php',
        __DIR__ . '/tests/symfony/config/routing.php',
        RemoveUnusedPrivateMethodParameterRector::class => [
            __DIR__ . '/src/symfony/src/DependencyInjection/Configuration.php',
        ],
        PreferPHPUnitThisCallRector::class,
    ]);
    $config->rule(ExplicitNullableParamTypeRector::class);
    $config->phpVersion(PhpVersion::PHP_82);
    $config::configure()->withComposerBased(twig: true, doctrine: true, phpunit: true);
    $config::configure()->withPhpSets();
    $config::configure()->withAttributesSets();

    $config->parallel();
    $config->importNames();
    $config->importShortClasses();
};
