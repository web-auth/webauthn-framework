<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Core\ValueObject\PhpVersion;
use Rector\DeadCode\Rector\ClassMethod\RemoveUnusedPrivateMethodParameterRector;
use Rector\Doctrine\Set\DoctrineSetList;
use Rector\PHPUnit\Set\PHPUnitLevelSetList;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\Symfony\Set\SymfonyLevelSetList;
use Rector\Symfony\Set\SymfonySetList;

return static function (RectorConfig $config): void {
    $config->import(SetList::DEAD_CODE);
    $config->import(LevelSetList::UP_TO_PHP_81);
    $config->import(SymfonyLevelSetList::UP_TO_SYMFONY_60);
    $config->import(SymfonySetList::SYMFONY_CODE_QUALITY);
    $config->import(SymfonySetList::SYMFONY_52_VALIDATOR_ATTRIBUTES);
    $config->import(SymfonySetList::SYMFONY_CONSTRUCTOR_INJECTION);
    $config->import(SymfonySetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->import(DoctrineSetList::DOCTRINE_CODE_QUALITY);
    $config->import(DoctrineSetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->import(PHPUnitSetList::PHPUNIT_EXCEPTION);
    $config->import(PHPUnitSetList::PHPUNIT_SPECIFIC_METHOD);
    $config->import(PHPUnitLevelSetList::UP_TO_PHPUNIT_100);
    $config->import(PHPUnitSetList::PHPUNIT_YIELD_DATA_PROVIDER);
    $config->paths([__DIR__ . '/src', __DIR__ . '/tests']);
    $config->skip([
        'src/symfony/src/DependencyInjection/Configuration.php',
        'src/symfony/src/Routing/Loader.php',
        'tests/symfony/config/routing.php',
        RemoveUnusedPrivateMethodParameterRector::class => [
            __DIR__ . '*/DependencyInjection/Configuration.php',
        ],
    ]);
    $config->phpVersion(PhpVersion::PHP_81);
    $config->parallel();
    $config->importNames();
    $config->importShortClasses();
};
