<?php

namespace Uecode\Bundle\ApiKeyBundle\Security\Http\Firewall;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Uecode\Bundle\ApiKeyBundle\Security\Core\Authentication\Token\ApiKeyUserToken;

/**
 * @author Aaron Scherer <aequasi@gmail.com>
 */
class ApiKeyListener implements ListenerInterface
{
    /**
     * @var SecurityContextInterface
     */
    private $securityContext;
    /**
     * @var AuthenticationManagerInterface
     */
    private $authenticationManager;
    /**
     * @var AuthenticationEntryPointInterface
     */
    private $authenticationEntryPoint;
    /**
     * @var string
     */
    private $providerKey;
    /**
     * @var LoggerInterface
     */
    private $logger;
    /**
     * @var array
     */
    private $checkMapping;
    /**
     * @var string
     */
    private $discriminator;

    /**
     * @param SecurityContextInterface $context
     * @param AuthenticationManagerInterface $manager
     * @param AuthenticationEntryPointInterface $entryPoint
     * @param string $providerKey
     * @param array $checkMapping
     * @param string $discriminator
     * @param LoggerInterface $logger
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(
        SecurityContextInterface $context,
        AuthenticationManagerInterface $manager,
        AuthenticationEntryPointInterface $entryPoint,
        $providerKey,
        array $checkMapping,
        $discriminator,
        LoggerInterface $logger = null)
    {
        if (empty($providerKey)) {
            throw new \InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->securityContext       = $context;
        $this->authenticationManager = $manager;
        $this->authenticationEntryPoint = $entryPoint;
        $this->providerKey = $providerKey;
        $this->checkMapping = $checkMapping;
        $this->discriminator = $discriminator;
        $this->logger = $logger;
    }

    /**
     * This interface must be implemented by firewall listeners.
     *
     * @param GetResponseEvent $event
     *
     * @throws \RuntimeException
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        $apiKey = $fetchType = $checkValue = false;

        //find out if the current request contains any information by which the user might be authenticated
        foreach (array('header_token', 'query_param', 'basic_auth') as $fetchType) {
            if (empty($this->checkMapping[$fetchType])) {
                continue;
            }

            $checkValue = $this->checkMapping[$fetchType];

            if (false !== $apiKey = $this->getApiKey($request, $fetchType, $checkValue)) {
                if ($this->logger) {
                    $this->logger->info(sprintf('Authorization %s[%s] found for %s api_key "%s".', $fetchType, $checkValue, json_encode($this->discriminator), $apiKey));
                }
                break;
            }
        }

        if (empty($apiKey)) {
            return;
        }

        $token = new ApiKeyUserToken('anon.', $apiKey, $this->discriminator, $this->providerKey);

        try {
            $returnValue = $this->authenticationManager->authenticate($token);

            if ($returnValue instanceof TokenInterface) {
                $this->securityContext->setToken($returnValue);
            } elseif ($returnValue instanceof Response) {
                $event->setResponse($returnValue);
            } else {
                throw new \RuntimeException('authenticate() must either return a Response or an implementation of TokenInterface.');
            }
        } catch (AuthenticationException $failed) {
            $token = $this->securityContext->getToken();

            if ($token instanceof ApiKeyUserToken && $this->providerKey === $token->getProviderKey()) {
                $this->securityContext->setToken(null);
            }

            if ($this->logger) {
                $this->logger->info(sprintf('Authorization %s[%s] failed for api_key "%s": %s', $fetchType, $checkValue, $apiKey, $failed->getMessage()));
            }

            $event->setResponse($this->authenticationEntryPoint->start($request));
        }
    }

    protected function getApiKey(Request $request, $type, $name)
    {
        switch ($type) {
            case 'basic_auth':
                return $request->headers->get('PHP_AUTH_USER', false);

            case 'query_param':
                return $request->query->get($name, false);

            case 'header_token':
                if (false === $header = $request->headers->get('Authorization')) {
                    return false;
                }

                $name .= ' '; // add spacer to match "Authorization: NAME api_key"
                $length = strlen($name);

                if (0 !== strpos($header, $name) || strlen($header) <= $length) {
                    return false;
                }

                return substr($header, $length);
        }

        throw new \RuntimeException(sprintf('Undefined type [%s] for api key.', $type));
    }
}
