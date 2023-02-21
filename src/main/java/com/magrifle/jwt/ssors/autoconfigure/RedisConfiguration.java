package com.magrifle.jwt.ssors.autoconfigure;

import com.magrifle.jwt.ssors.service.LoggedOutTokenService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

@ConditionalOnProperty(name = "authentication.redis.host")
@Configuration
public class RedisConfiguration
{
    @Value("${authentication.redis.host}")
    private String hostName;

    @Value("${authentication.redis.port:6379}")
    private int port;


    @Bean(name = "jtiCheckerJedisConnectionFactory")
    JedisConnectionFactory jedisConnectionFactory()
    {
        RedisStandaloneConfiguration redisStandaloneConfiguration = new RedisStandaloneConfiguration(hostName, port);
        return new JedisConnectionFactory(redisStandaloneConfiguration);
    }


    @Bean(name = "jtiCheckerRedisTemplate")
    RedisTemplate<String, String> redisTemplate(@Qualifier("jtiCheckerJedisConnectionFactory") JedisConnectionFactory jedisConnectionFactory)
    {
        RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(jedisConnectionFactory);
        return redisTemplate;
    }


    @Bean
    public LoggedOutTokenService loggedOutTokenService(@Qualifier("jtiCheckerRedisTemplate") RedisTemplate redisTemplate)
    {
        return new LoggedOutTokenService(redisTemplate);
    }
}
