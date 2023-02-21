package io.github.magrifle.jwt.ssors.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;

public class LoggedOutTokenService
{
    private static final Logger logger = LoggerFactory.getLogger(LoggedOutTokenService.class);

    private RedisTemplate redisTemplate;


    public LoggedOutTokenService(RedisTemplate redisTemplate)
    {
        this.redisTemplate = redisTemplate;
    }


    public boolean isBlackedListedJti(String jti)
    {
        try
        {
            return redisTemplate.opsForValue().get(jti) != null;
        }
        catch (Exception e)
        {
            logger.warn("An error occurred while checking jti in redis, but this would not stop the normal behaviour of the application.", e);
            return true;
        }
    }

}
