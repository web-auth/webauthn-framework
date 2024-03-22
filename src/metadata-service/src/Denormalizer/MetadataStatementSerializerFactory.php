<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Denormalizer;

use Symfony\Component\PropertyInfo\Extractor\PhpDocExtractor;
use Symfony\Component\PropertyInfo\Extractor\ReflectionExtractor;
use Symfony\Component\PropertyInfo\PropertyInfoExtractor;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\ArrayDenormalizer;
use Symfony\Component\Serializer\Normalizer\ObjectNormalizer;
use Symfony\Component\Serializer\Normalizer\UidNormalizer;
use Symfony\Component\Serializer\Serializer;
use Symfony\Component\Serializer\SerializerInterface;

final class MetadataStatementSerializerFactory
{
    private const PACKAGE_SYMFONY_PROPERTY_INFO = 'symfony/property-info';

    private const PACKAGE_SYMFONY_SERIALIZER = 'symfony/serializer';

    private const PACKAGE_PHPDOCUMENTOR_REFLECTION_DOCBLOCK = 'phpdocumentor/reflection-docblock';

    public static function create(): ?SerializerInterface
    {
        foreach (self::getRequiredSerializerClasses() as $class => $package) {
            if (! class_exists($class)) {
                return null;
            }
        }

        $denormalizers = [
            new ExtensionDescriptorDenormalizer(),
            new UidNormalizer(),
            new ArrayDenormalizer(),
            new ObjectNormalizer(
                propertyTypeExtractor: new PropertyInfoExtractor(typeExtractors: [
                    new PhpDocExtractor(),
                    new ReflectionExtractor(),
                ])
            ),
        ];

        return new Serializer($denormalizers, [new JsonEncoder()]);
    }

    /**
     * @return array<class-string, string>
     */
    private static function getRequiredSerializerClasses(): array
    {
        return [
            UidNormalizer::class => self::PACKAGE_SYMFONY_SERIALIZER,
            ArrayDenormalizer::class => self::PACKAGE_SYMFONY_SERIALIZER,
            ObjectNormalizer::class => self::PACKAGE_SYMFONY_SERIALIZER,
            PropertyInfoExtractor::class => self::PACKAGE_SYMFONY_PROPERTY_INFO,
            PhpDocExtractor::class => self::PACKAGE_PHPDOCUMENTOR_REFLECTION_DOCBLOCK,
            ReflectionExtractor::class => self::PACKAGE_SYMFONY_PROPERTY_INFO,
            JsonEncoder::class => self::PACKAGE_SYMFONY_SERIALIZER,
            Serializer::class => self::PACKAGE_SYMFONY_SERIALIZER,
        ];
    }
}
