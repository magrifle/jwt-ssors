### Description
The library that helps auto-configure a springboot application as a resource server for oauth2 based authorization. It uses the jwt format determine what scopes are available for the current user and sets the corresponding spring authentication object in the security context

### Usage
1) Add the library as a mvn dependency in your project

```xml

        <dependency>
            <groupId>io.github.magrifle</groupId>
            <artifactId>jwt-ssors</artifactId>
        </dependency>
```
2) Add some configurations in your application properties as you desire. At the moment, the library uses an `RSA` based token verification mode as opposed to a pre-shared key that means you need to set a public key using the property `jwt.ssors.public-key`

Then you can protect access to resources based on different authorities. You can also get the authenticated user details from the 
security context such as user phone number.

```java
import io.github.magrifle.jwt.ssors.dto.AuthenticatedUser;
import io.github.magrifle.jwt.ssors.annotation.CurrentUser;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {
    @PreAuthorize("hasAuthority('user:read')")
    @GetMapping("/hello")
    public String hello(@CurrentUser AuthenticatedUser user) {
        // user.getId() or user.getPrincipal() will give you the current user's id that was encoded in the access_token
        return String.format("userId: %s with email: %s and roles: %s", user.getId(), user.getEmail(), user.getAuthorities());
    }
}

```
