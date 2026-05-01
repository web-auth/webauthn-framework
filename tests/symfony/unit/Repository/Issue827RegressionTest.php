<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Repository;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use ReflectionNamedType;
use function sprintf;
use Webauthn\Bundle\Controller\AssertionControllerFactory;
use Webauthn\Bundle\Controller\AssertionResponseController;
use Webauthn\Bundle\Controller\AttestationControllerFactory;
use Webauthn\Bundle\Controller\AttestationResponseController;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedCreationOptionsBuilder;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedRequestOptionsBuilder;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Security\Authentication\WebauthnBadgeListener;
use Webauthn\Bundle\Security\Http\Authenticator\WebauthnAuthenticator;

/**
 * Issue #827: classes inside the bundle used to type-hint the deprecated
 * PublicKeyCredentialSourceRepositoryInterface, so a user repository implementing only the new
 * CredentialRecordRepositoryInterface could not be autowired. Each constructor below must now
 * accept the new interface.
 *
 * @internal
 */
final class Issue827RegressionTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string, string}>
     */
    public static function bundleClassesExpectingCredentialRepository(): iterable
    {
        yield 'WebauthnAuthenticator' => [WebauthnAuthenticator::class, 'publicKeyCredentialSourceRepository'];
        yield 'WebauthnBadgeListener' => [WebauthnBadgeListener::class, 'publicKeyCredentialSourceRepository'];
        yield 'AttestationResponseController' => [
            AttestationResponseController::class,
            'credentialSourceRepository',
        ];
        yield 'AssertionResponseController' => [
            AssertionResponseController::class,
            'publicKeyCredentialSourceRepository',
        ];
        yield 'AttestationControllerFactory' => [
            AttestationControllerFactory::class,
            'publicKeyCredentialSourceRepository',
        ];
        yield 'AssertionControllerFactory' => [
            AssertionControllerFactory::class,
            'publicKeyCredentialSourceRepository',
        ];
        yield 'ProfileBasedCreationOptionsBuilder' => [
            ProfileBasedCreationOptionsBuilder::class,
            'credentialSourceRepository',
        ];
        yield 'ProfileBasedRequestOptionsBuilder' => [
            ProfileBasedRequestOptionsBuilder::class,
            'credentialSourceRepository',
        ];
    }

    #[Test]
    #[DataProvider('bundleClassesExpectingCredentialRepository')]
    public function constructorAcceptsTheNewCredentialRecordRepositoryInterface(
        string $class,
        string $parameterName
    ): void {
        $constructor = new ReflectionMethod($class, '__construct');

        $matchingParameter = null;
        foreach ($constructor->getParameters() as $parameter) {
            if ($parameter->getName() === $parameterName) {
                $matchingParameter = $parameter;
                break;
            }
        }

        static::assertNotNull(
            $matchingParameter,
            sprintf('Class %s should have a constructor parameter named "%s".', $class, $parameterName)
        );

        $type = $matchingParameter->getType();
        static::assertInstanceOf(ReflectionNamedType::class, $type);
        static::assertSame(
            CredentialRecordRepositoryInterface::class,
            $type->getName(),
            sprintf(
                'Class %s::__construct(...$%s) must accept the new CredentialRecordRepositoryInterface so that user repositories implementing only the new interface can be autowired (issue #827). Was: %s.',
                $class,
                $parameterName,
                $type->getName()
            )
        );
    }

    #[Test]
    public function deprecatedRepositoryInterfaceStillExtendsTheNewOne(): void
    {
        // BC: a 5.2.x user repository implementing the legacy interface must still be injectable
        // wherever the bundle now requires the new interface.
        $reflection = new ReflectionClass(PublicKeyCredentialSourceRepositoryInterface::class);

        static::assertTrue($reflection->implementsInterface(CredentialRecordRepositoryInterface::class));
    }
}
