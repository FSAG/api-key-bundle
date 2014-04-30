<?php

namespace Uecode\Bundle\ApiKeyBundle\Security\Core\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\ChainUserProvider;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Uecode\Bundle\ApiKeyBundle\Security\Core\Authentication\Token\ApiKeyUserToken;
use Uecode\Bundle\ApiKeyBundle\Security\Core\User\ApiKeyUserProviderInterface;

/**
 * @author Aaron Scherer <aequasi@gmail.com>
 */
class ApiKeyProvider implements AuthenticationProviderInterface
{
    /**
     * @var UserProviderInterface
     */
    private $userProvider;
    /**
     * @var UserCheckerInterface
     */
    private $userChecker;
    /**
     * @var string
     */
    private $providerKey;
    /**
     * @var boolean
     */
    private $hideUserNotFoundExceptions;

    /**
     * Constructor.
     *
     * @param UserProviderInterface $userProvider An UserProviderInterface instance
     * @param UserCheckerInterface $userChecker An UserCheckerInterface instance
     * @param string $providerKey The provider key
     * @param boolean $hideUserNotFoundExceptions
     */
    public function __construct(UserProviderInterface $userProvider, UserCheckerInterface $userChecker, $providerKey, $hideUserNotFoundExceptions = true)
    {
        $this->userProvider = $userProvider;
        $this->userChecker = $userChecker;
        $this->providerKey = $providerKey;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
    }

    /**
      * {@inheritdoc}
      *
      * @param ApiKeyUserToken $token
      */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return null;
        }

        try {
            $user = $this->retrieveUser($token);

            if (!$user instanceof UserInterface) {
                throw new AuthenticationServiceException('retrieveUser() must return a UserInterface.');
            }
        } catch (UsernameNotFoundException $e) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $e);
            }
            throw $e;
        } catch (\Exception $error) {
            $ex = new AuthenticationServiceException($error->getMessage(), 0, $error);
            $ex->setToken($token);
            throw $ex;
        }

        try {
            $this->userChecker->checkPreAuth($user, $token->getDiscriminator());
            $this->checkAuthentication($user, $token);
            $this->userChecker->checkPostAuth($user, $token->getDiscriminator());
        } catch (BadCredentialsException $e) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $e);
            }

            throw $e;
        }

        $authenticatedToken = new ApiKeyUserToken($user, $token->getApiKey(), $token->getDiscriminator(), $this->providerKey, $user->getRoles());
        $authenticatedToken->setAttributes($token->getAttributes());

        return $authenticatedToken;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof ApiKeyUserToken && $this->providerKey === $token->getProviderKey();
    }

    /**
     * Retrieves the user from an implementation-specific location.
     *
     * @param ApiKeyUserToken $token The Token
     *
     * @return UserInterface The user
     * @throws \RuntimeException
     */
    protected function retrieveUser(ApiKeyUserToken $token)
    {
        $user = $token->getUser();

        if ($user instanceof UserInterface) {
            return $user;
        }

        if (null === $token->getApiKey()) {
            throw new BadCredentialsException('No API key found in request.');
        }

        if ($this->userProvider instanceof ChainUserProvider) {
            foreach ($this->userProvider->getProviders() as $provider) {
                if ($provider instanceof ApiKeyUserProviderInterface) {
                    try {
                        return $provider->loadUserByApiKey($token->getApiKey(), $token->getDiscriminator());
                    } catch (UsernameNotFoundException $notFound) {
                        // try next one
                    }
                }

                $ex = new UsernameNotFoundException('User could not be found.');
                throw $ex;
            }
        }

        if ($this->userProvider instanceof ApiKeyUserProviderInterface) {
            return $this->userProvider->loadUserByApiKey($token->getApiKey(), $token->getDiscriminator());
        }

        throw new \RuntimeException(sprintf(
            '%s class must implement Uecode\Bundle\ApiKeyBundle\Security\Core\User\ApiKeyUserProviderInterface interface.'
            , get_class($this->userProvider)));
    }

    /**
     * Does additional checks on the user and token (like extra validating)
     *
     * @param UserInterface   $user
     * @param ApiKeyUserToken $token
     *
     * @throws AuthenticationException if the user could not be validated
     */
    protected function checkAuthentication(UserInterface $user, ApiKeyUserToken $token)
    {
    }
}
