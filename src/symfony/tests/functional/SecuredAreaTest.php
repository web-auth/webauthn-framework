<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group functional
 */
class SecuredAreaTest extends WebTestCase
{
    /**
     * @test
     */
    public function aClientIsRedirectedIfUserIsNotAuthenticated()
    {
        $client = static::createClient();
        $client->request('GET', '/admin', [], [], ['HTTPS' => 'on']);

        static::assertEquals(302, $client->getResponse()->getStatusCode());
        static::assertTrue($client->getResponse()->headers->has('location'));
        static::assertEquals('https://localhost/login', $client->getResponse()->headers->get('location'));
    }

    /**
     * @test
     */
    public function aUserCanSetHisUsernameToTheLoginPage()
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/login', [], [], ['HTTPS' => 'on']);

        static::assertEquals(200, $client->getResponse()->getStatusCode());
        dump($client->getResponse()->getContent());

        $button = $crawler->selectButton('_submit');
        $form = $button->form();
        $client->submit($form, [
            '_username' => 'root',
        ]);

        //$client->followRedirect();
        //dump($client->getHistory());
        //dump($client->getResponse()->getContent());
    }
}
