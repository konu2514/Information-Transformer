# Information-Transformer

Caused by: org.springframework.beans.factory.UnsatisfiedDependencyException: Error creating bean with name 'jwtAuthFilter' defined in file [C:\Users\manjunath.konu\IdeaProjects\PolicyVault\target\classes\org\godigit\policyvault\security\JwtAuthFilter.class]: Unsatisfied dependency expressed through constructor parameter 0: Error creating bean with name 'jwtUtils' defined in file [C:\Users\manjunath.konu\IdeaProjects\PolicyVault\target\classes\org\godigit\policyvault\security\JwtUtils.class]: Unsatisfied dependency expressed through constructor parameter 1: Failed to convert value of type 'java.lang.String' to required type 'long'; For input string: "86400000#24hinms"

# JWT
app.jwt.secret=change-this-super-long-random-secret
app.jwt.expiration-ms=86400000  # 24h in ms

