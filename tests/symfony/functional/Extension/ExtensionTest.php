<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Extension;

use CBOR\Decoder;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Webauthn\AuthenticationExtensions\ExtensionManager;
use Webauthn\AuthenticationExtensions\Uvm\UvmExtension;
use Webauthn\StringStream;

/**
 * @internal
 */
final class ExtensionTest extends KernelTestCase
{
    #[Test]
    public function theExtensionCanBeLoaded(): void
    {
        //Given
        $data = new StringStream(hex2bin('A16375766d828302040283040101'));
        $cbor = Decoder::create()->decode($data);

        $extensionManager = new ExtensionManager();
        $extensionManager->add(new UvmExtension());

        //When
        $outputs = $extensionManager->loadFromOutput($cbor->normalize());

        //Then
        static::assertTrue($outputs->has('uvm'));
        $output = $outputs->get('uvm');
        dd($output);
    }
}
