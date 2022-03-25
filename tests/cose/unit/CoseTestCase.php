<?php

declare(strict_types=1);

namespace Cose\Tests\Unit;

use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Mac\HS256Truncated64;
use Cose\Algorithm\Mac\HS384;
use Cose\Algorithm\Mac\HS512;
use Cose\Algorithm\ManagerFactory;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\EdDSA\Ed256;
use Cose\Algorithm\Signature\EdDSA\Ed512;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
abstract class CoseTestCase extends TestCase
{
    private null|ManagerFactory $managerFactory = null;

    protected function getFactory(): ManagerFactory
    {
        if ($this->managerFactory === null) {
            $this->managerFactory = ManagerFactory::create()
                ->add('HS256', HS256::create())
                ->add('HS256/64', HS256Truncated64::create())
                ->add('HS384', HS384::create())
                ->add('HS512', HS512::create())

                ->add('Ed256', Ed256::create())
                ->add('Ed512', Ed512::create())
                ->add('Ed25519', Ed25519::create())

                ->add('PS256', PS256::create())
                ->add('PS384', PS384::create())
                ->add('PS512', PS512::create())

                ->add('RS256', RS256::create())
                ->add('RS384', RS384::create())
                ->add('RS512', RS512::create())
            ;
        }

        return $this->managerFactory;
    }
}
