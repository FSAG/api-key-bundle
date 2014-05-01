<?php

namespace Uecode\Bundle\ApiKeyBundle\Security\Core\User;

use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\User\UserChecker;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @author Nikolai Zujev <nikolai.zujev@gmail.com>
 */
class ApiKeyUserChecker extends UserChecker
{
    /**
     * {@inheritdoc}
     *
     * @param string|null $discriminator The discriminator of the api key
     */
    public function checkPreAuth(UserInterface $user, $discriminator = null)
    {
        parent::checkPreAuth($user);

        if (!$user instanceof ApiKeyUserInterface) {
            return;
        }

        if (!$user->isApiKeyEnabled($discriminator)) {
            $ex = new CredentialsExpiredException('User api_key is not enabled.');
            $ex->setUser($user);
            throw $ex;
        }
    }

    /**
     * {@inheritdoc}
     *
     * @param string|null $discriminator The discriminator of the api key
     */
    public function checkPostAuth(UserInterface $user, $discriminator = null)
    {
        if (!$user instanceof ApiKeyUserInterface) {
            return;
        }

        if (!$user->isApiKeyNonExpired($discriminator)) {
            $ex = new CredentialsExpiredException('User api_key has expired.');
            $ex->setUser($user);
            throw $ex;
        }
    }
}
