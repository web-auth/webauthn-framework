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
            UidNormalizer::class => 'symfony/serializer',
            ArrayDenormalizer::class => 'symfony/serializer',
            ObjectNormalizer::class => 'symfony/serializer',
            PropertyInfoExtractor::class => 'symfony/serializer',
            PhpDocExtractor::class => 'phpdocumentor/reflection-docblock',
            ReflectionExtractor::class => 'symfony/serializer',
            JsonEncoder::class => 'symfony/serializer',
            Serializer::class => 'symfony/serializer',
        ];
    }
}
