<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * The authenticator selection criteria of a profile are available on their own, so that a caller letting the client
 * override some members can keep the profile value of the others.
 *
 * @internal
 */
final class PublicKeyCredentialCreationOptionsFactoryTest extends TestCase
{
    #[Test]
    public function theCriteriaOfTheProfileAreAvailable(): void
    {
        $criteria = self::factory()->getAuthenticatorSelectionCriteria('strict');

        static::assertSame(AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM, $criteria->authenticatorAttachment);
        static::assertSame(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED, $criteria->userVerification);
        static::assertSame(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED, $criteria->residentKey);
        static::assertTrue($criteria->requireResidentKey);
    }

    #[Test]
    public function theOptionsUseTheCriteriaOfTheProfileWhenNoneIsGiven(): void
    {
        $factory = self::factory();

        $options = $factory->create(
            'strict',
            PublicKeyCredentialUserEntity::create('john.doe', 'user-handle', 'John Doe')
        );

        static::assertEquals($factory->getAuthenticatorSelectionCriteria('strict'), $options->authenticatorSelection);
    }

    #[Test]
    public function theCriteriaOfAnUnknownProfileAreRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The profile with key "unknown" does not exist.');

        self::factory()->getAuthenticatorSelectionCriteria('unknown');
    }

    #[Test]
    public function theOptionsOfAnUnknownProfileAreRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The profile with key "unknown" does not exist.');

        self::factory()->create('unknown', PublicKeyCredentialUserEntity::create('john.doe', 'user-handle', 'John Doe'));
    }

    private static function factory(): PublicKeyCredentialCreationOptionsFactory
    {
        return new PublicKeyCredentialCreationOptionsFactory([
            'strict' => [
                'rp' => [
                    'name' => 'Example',
                    'id' => 'example.com',
                ],
                'challenge_length' => 32,
                'authenticator_selection_criteria' => [
                    'authenticator_attachment' => AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
                    'user_verification' => AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                    'resident_key' => AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
                ],
                'public_key_credential_parameters' => [-7],
                'extensions' => [],
            ],
        ]);
    }
}
