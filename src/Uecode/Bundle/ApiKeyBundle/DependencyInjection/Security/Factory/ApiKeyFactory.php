<?php

namespace Uecode\Bundle\ApiKeyBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

/**
 * @author Aaron Scherer <aequasi@gmail.com>
 */
class ApiKeyFactory implements SecurityFactoryInterface
{

    public function getPosition()
    {
        return 'pre_auth';
    }

    public function getKey()
    {
        return 'api_key';
    }

    public function addConfiguration(NodeDefinition $builder)
    {
        $builder
            ->treatTrueLike(array('query_param'=>'api_key'))
            ->treatFalseLike(array('query_param'=>'api_key'))
            ->treatNullLike(array('query_param'=>'api_key'))
            ->children()
                ->scalarNode('provider')->end()
                ->scalarNode('realm')->defaultValue('Secured API')->end()
                ->scalarNode('discriminator')->defaultNull()->end()
                ->scalarNode('query_param')->cannotBeEmpty()->defaultFalse()->end()
                ->scalarNode('header_token')->cannotBeEmpty()->defaultFalse()->end()
                ->booleanNode('basic_auth')->cannotBeEmpty()->defaultFalse()->end()
            ->end()
            ->validate()
                ->ifTrue(function ($v) { return empty($v['header_token']) && empty($v['query_param']) && empty($v['basic_auth']); })
                ->thenInvalid('At least one of [query_param, header_token, basic_auth] parameters must be configured.')
            ->end()
        ;
    }

    public function create(ContainerBuilder $container, $id, $config, $userProviderId, $defaultEntryPointId)
    {
        // authentication provider
        $authProviderId = $this->createAuthProvider($container, $id, $config, $userProviderId);

        // authentication entry point
        $entryPointId = $this->createEntryPoint($container, $id, $config, $defaultEntryPointId);

        // authentication listener
        $listenerId = $this->createListener($container, $id, $config, $entryPointId);

        return array($authProviderId, $listenerId, $entryPointId);
    }

    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {
        $providerId = 'security.authentication.provider.api_key.' . $id;

        $container
            ->setDefinition($providerId, new DefinitionDecorator('uecode.api_key.provider.api_key'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(2, $id)
        ;

        return $providerId;
    }

    protected function createEntryPoint(ContainerBuilder $container, $id, $config, $defaultEntryPointId)
    {
        $entryPointId = 'security.authentication.entry_point.api_key.' . $id;

        $container
            ->setDefinition($entryPointId, new DefinitionDecorator('uecode.api_key.entry_point.api_key'))
            ->replaceArgument(0, $config['basic_auth'] ? 'Basic' : ($config['header_token'] ?: ($config['query_param'] ? 'QueryString' : null)))
            ->replaceArgument(1, $config['realm'])
        ;

        return $entryPointId;
    }

    protected function createListener(ContainerBuilder $container, $id, $config, $entryPointId)
    {
        $checkMapping = array_intersect_key($config, array(
            'query_param'  => true,
            'header_token' => true,
            'basic_auth'   => true,
        ));

        $listenerId = 'security.authentication.listener.api_key.' . $id;
        $container
            ->setDefinition($listenerId, new DefinitionDecorator('uecode.api_key.listener.api_key'))
            ->replaceArgument(2, new Reference($entryPointId))
            ->replaceArgument(3, $id)
            ->replaceArgument(4, $checkMapping)
            ->replaceArgument(5, $config['discriminator'])
        ;

        return $listenerId;
    }
}
