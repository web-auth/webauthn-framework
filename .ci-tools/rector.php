<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\DeadCode\Rector\Property\RemoveDefaultValueFromAssignedPropertyRector;
use Rector\Doctrine\Set\DoctrineSetList;
use Rector\Php80\Rector\Class_\ClassPropertyAssignToConstructorPromotionRector;
use Rector\Php81\Rector\Property\ReadOnlyPropertyRector;
use Rector\Php82\Rector\Class_\ReadOnlyClassRector;
use Rector\PHPUnit\CodeQuality\Rector\Class_\PreferPHPUnitThisCallRector;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\Symfony\Symfony80\Rector\Class_\RemoveEraseCredentialsRector;
use Rector\ValueObject\PhpVersion;

$builder = RectorConfig::configure();
if (file_exists('/tools/.composer/vendor-bin/phpunit/vendor/autoload.php')) {
    $builder->withAutoloadPaths(['/tools/.composer/vendor-bin/phpunit/vendor/autoload.php']);
}
$builder->withSets([
    SetList::DEAD_CODE,
    LevelSetList::UP_TO_PHP_82,
    DoctrineSetList::DOCTRINE_CODE_QUALITY,
    DoctrineSetList::ANNOTATIONS_TO_ATTRIBUTES,
    PHPUnitSetList::PHPUNIT_CODE_QUALITY,
    PHPUnitSetList::ANNOTATIONS_TO_ATTRIBUTES,
]);
$builder->withComposerBased(twig: true, doctrine: true, symfony: true);
$builder->withPhpVersion(PhpVersion::PHP_82);
$builder->withPaths(
    [
        __DIR__ . '/../src',
        __DIR__ . '/../tests',
        __DIR__ . '/../castor.php',
        __DIR__ . '/ecs.php',
        __DIR__ . '/rector.php',
    ]
);
// `Item::$ceremonyOrigin` must stay a plain property with a default so that
// ceremonies serialized before the property existed still unserialize into a
// usable object. See the class docblock.
$itemStorage = [__DIR__ . '/../src/symfony/src/Security/Storage/Item.php'];
$builder->withSkip([
    PreferPHPUnitThisCallRector::class,
    RemoveEraseCredentialsRector::class,
    ClassPropertyAssignToConstructorPromotionRector::class => $itemStorage,
    ReadOnlyClassRector::class => $itemStorage,
    ReadOnlyPropertyRector::class => $itemStorage,
    RemoveDefaultValueFromAssignedPropertyRector::class => $itemStorage,
    __DIR__ . '/../src/Library/Core/JWKSet.php',
    __DIR__ . '/../src/Bundle/JoseFramework/DependencyInjection/Source/KeyManagement/JWKSource.php',
    __DIR__ . '/../src/Bundle/JoseFramework/DependencyInjection/Source/KeyManagement/JWKSetSource.php',
]);
$builder->withParallel();
$builder->withImportNames();

return $builder;
