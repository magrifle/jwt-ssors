package com.magrifle.jwt.ssors.autoconfigure;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;


@Data
@Component
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "jwt.ssors")
public class MagrifleResourceServerProperties {

    private String publicKey = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkVLAlBpRWtxrhieQ4zq6
            rbMLNtKMDOtQcJ+pkNCTjpUM7wb7YmmSUJ8aHHy2Cb+F0pLBmzp0XrIsA37lm5G+
            XoOu/tSzeIroeSvBxZ/0HNTcJSmZK48ZOH+PA01mgT7HcXTE2+zHatA5J1qW1A13
            v1NWPqfqUaEHJBCHA4OMS9EHDeCnUMwozXITudBko6xsxAZo6M4vjI1ovlG9rUJv
            FbRhy7nFot4HwwxqMmcXEi46gbx6k6xrWbeO2LBXomV+sI7EgXRmZRlygke4svT9
            9uiiTr1Z6Q/BI1bL+6uk0MtLObEPN8KVj8lKEJ2coCgB6xuRwcI5dJFxdfaXnh9+
            AwIDAQAB
            -----END PUBLIC KEY-----
            """;

    private String scopeKey = "scope";

    private boolean scopesGrouped = false;

    private String scopeDelimeter = " ";

}
