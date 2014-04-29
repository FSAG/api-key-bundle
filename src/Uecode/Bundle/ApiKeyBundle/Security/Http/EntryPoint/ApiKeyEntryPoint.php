<?php

namespace Uecode\Bundle\ApiKeyBundle\Security\Http\EntryPoint;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;

/**
 * @author Nikolai Zujev <nikolai.zujev@gmail.com>
 */
class ApiKeyEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * @var string
     */
    private $challenge;
    /**
     * @var string
     */
    private $realmName;

    /**
     * @param string $challenge
     * @param string $realmName
     */
    public function __construct($challenge, $realmName)
    {
        $this->challenge = $challenge;
        $this->realmName = $realmName;
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $response = new Response();
        $response->setStatusCode(401);

        if ($this->challenge && $this->realmName) {
            $response->headers->set('WWW-Authenticate', sprintf('%s realm="%s"', $this->challenge, $this->realmName));
        }

        return $response;
    }
}
