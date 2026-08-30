<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Repository;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Tests\Bundle\Functional\CredentialRecordAppKernel;
use Webauthn\Tests\Bundle\Functional\CredentialRecordRepository;

/**
 * Issue #938: the BC alias on the deprecated PublicKeyCredentialSourceRepositoryInterface made the container invalid
 * for applications whose repository only implements CredentialRecordRepositoryInterface.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/938
 * @internal
 */
final class CredentialRepositoryAliasTest extends KernelTestCase
{
    #[Test]
    public function theContainerIsValidWithARepositoryImplementingOnlyTheNewInterfaces(): void
    {
        // Given
        $kernel = static::bootKernel();
        $application = new Application($kernel);
        $application->setAutoExit(false);
        $output = new BufferedOutput();

        // When
        $status = $application->run(new ArrayInput([
            'command' => 'lint:container',
        ]), $output);

        // Then
        static::assertSame(Command::SUCCESS, $status, $output->fetch());
    }

    #[Test]
    public function theDeprecatedInterfaceIsNotAliasedWhenTheRepositoryDoesNotImplementIt(): void
    {
        // Given
        static::bootKernel();
        $container = static::getContainer();

        // Then
        static::assertInstanceOf(
            CredentialRecordRepository::class,
            $container->get(CredentialRecordRepositoryInterface::class)
        );
        static::assertFalse($container->has(PublicKeyCredentialSourceRepositoryInterface::class));
    }

    protected static function getKernelClass(): string
    {
        return CredentialRecordAppKernel::class;
    }
}
