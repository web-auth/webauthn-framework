<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\DeadCode\Rector\ClassMethod\RemoveUnusedPrivateMethodParameterRector;
use Rector\Doctrine\Set\DoctrineSetList;
use Rector\Php81\Rector\Property\ReadOnlyPropertyRector;
use Rector\PHPUnit\CodeQuality\Rector\Class_\PreferPHPUnitThisCallRector;
//use Rector\PHPUnit\Set\PHPUnitLevelSetList;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
//use Rector\Symfony\Set\SymfonyLevelSetList;
use Rector\Symfony\Set\SymfonySetList;
use Rector\ValueObject\PhpVersion;

return static function (RectorConfig $config): void {
    $config->import(SetList::DEAD_CODE);
    $config->import(LevelSetList::UP_TO_PHP_81);
    $config->import(SymfonySetList::SYMFONY_60);
    $config->import(SymfonySetList::SYMFONY_50_TYPES);
    $config->import(SymfonySetList::SYMFONY_52_VALIDATOR_ATTRIBUTES);
    $config->import(SymfonySetList::SYMFONY_CODE_QUALITY);
    $config->import(SymfonySetList::SYMFONY_CONSTRUCTOR_INJECTION);
    $config->import(SymfonySetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->import(DoctrineSetList::DOCTRINE_CODE_QUALITY);
    $config->import(DoctrineSetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->import(PHPUnitSetList::PHPUNIT_CODE_QUALITY);
    $config->import(PHPUnitSetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->import(PHPUnitSetList::PHPUNIT_100);
    $config->paths([__DIR__ . '/src', __DIR__ . '/tests', __DIR__ . '/ecs.php', __DIR__ . '/rector.php']);
    $config->skip([
        __DIR__ . '/src/symfony/src/DependencyInjection/Configuration.php',
        __DIR__ . '/src/symfony/src/Routing/Loader.php',
        __DIR__ . '/tests/symfony/config/routing.php',
        RemoveUnusedPrivateMethodParameterRector::class => [
            __DIR__ . '/src/symfony/src/DependencyInjection/Configuration.php',
        ],
        ReadOnlyPropertyRector::class => [__DIR__ . '/src/metadata-service/src/Statement/MetadataStatement.php'],
        PreferPHPUnitThisCallRector::class,
    ]);
    $config->phpVersion(PhpVersion::PHP_81);
    $config->parallel();
    $config->importNames();
    $config->importShortClasses();
};
