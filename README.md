# spring-security-demo
spring-security-demo

Spring Security - Complete Guide

- Security Principles
- Authentication - is it the right user?
- Authorization - do they have the right access?
- Spring Security Fundamentals
- Spring Security Filter Chain
- Form Authentication
- Basic Authentication
- JWT Authentication
- CSRF, CORS, ..
- OAuth

Understanding Security Fundamentals
- In any system:
    - You have resources
        - A REST API, A Web Application, A Database, A resource in the cloud, ...
    - You have identities
        - Identities need to access to resources and perform actions
            - For example: Execute a REST API call, Read/modify data in a database \
    - Key Questions:
        - How to identify users?
        - How to configure resources they can access & actions that are allowed?
- Authentication (is it the right user?)
    - UserId/password (What do you remember?)
    - Biometrics (What do you possess?)
- Authorization (do they have the right access?)
    - User XYZ can only read data
    - User ABC can read and update data

Understanding Important Security Principles
- A chain is only as strong as its WEAKEST link
    - Small security flaw makes an app with robust architecture vulnerable
- 6 Principles Of Building Secure Systems
    - 1: Trust Nothing
        - Validate every request
        - Validate piece of data or information that comes into the system
    - 2: Assign Least Privileges
        - Start the design of the system with security requirements in mind
        - Have a clear picture of the user roles and accesses
        - Assign Minimum Possible Privileges at all levels
            - Application
            - Infrastructure (database + server + ..)
    - 3: Have Complete Mediation
        - How were Medieval Fort's protected?
            - Everyone had to pass through one main gate
        - Apply a well-implemented security filter. Test the role and access of each user.
    - 4: Have Defense In Depth
        - Multiple levels of security
            - Transport, Network, Infrastructure
            - Operating System, Application, ..
    - 5: Have Economy Of Mechanism
        - Security architecture should be simple
        - Simple systems are easier to protect
    - 6: Ensure Openness Of Design
        - Easier to identify and fix security flaws
        - Opposite of the misplaced idea of "Security Through Obscurity"


Getting Started with Spring Security
- Security is the NO 1 priority for enterprises today!
- What is the most popular security project in the Spring eco-system?
    - Spring Security: Protect your web applications, REST API and microservices
    - Spring Security can be difficult to get started
        - Filter Chain
        - Authentication managers
        - Authentication providers ...
- BUT it provides a very flexible security system!
    - By default, everything is protected!
    - A chain of filters ensure proper authentication and authorization

Spring Security Flow

Request -> Spring Security -> Dispatcher Servlet -> Controllers

- Spring security intercepts all requests
- Follows following security principle
    - 3: Have Complete Mediation
- Spring security executes a series of filters
    - Also called Spring Security Filter Chain

CORS filter- Cross Origin Request Sharing
CSRF filter- Cross site request forgery.
BasicAuthenticationFilter
AuthorizationFilter


How does Spring Security Work? (2)
- Spring Security executes a series of filters
    - Filters provide these features:
        - Authentication: Is it a valid user? (Ex: BasicAuthenticationFilter)
        - Authorization: Does the user have right access?(Ex: AuthorizationFilter)
    - Other Features:
        - Cross-Origin Resource Sharing (CORS) - CorsFilter
            - Should you allow AJAX calls from other domains?
        - Cross Site Request Forgery (CSRF) - CsrfFilter
            - A malicious website making use of previous authentication on your website
            - Default: CSRF protection enabled for update requests - POST, PUT etc..
        - Login Page, Logout Page
            - LogoutFilter, DefaultLoginPageGeneratingFilter, DefaultLogoutPageGeneratingFilter
        - Translating exceptions into proper Http Responses (ExceptionTranslationFilter)
- Order of filters is important (typical order shown below)
    - 1: Basic Check Filters - CORS, CSRF, ..
    - 2: Authentication Filters
    - 3: Authorization Filters

Default Spring Security Configuration
- Everything is authenticated
    - You can customize it further
- Form authentication is enabled (with default form and logout features)
- Basic authentication is enabled Test user is created
    - Credentials printed in log (Username is user)
- CSRF protection is enabled
- CORS requests are denied
- X-Frame-Options is set to 0 (Frames are disabled)
- And a lot of others...


Exploring Form Based Authentication
- Used by most web applications
- Uses a Session Cookie
    - JSESSIONID: E2E693A57F6F7E4AC112A1BF4D40890A
- Spring security enables form based authentication by default
- Provides a default Login Page Provides a default Logout Page Provides a /logout URL
- You can add a change password page
    - (http.passwordManagement(Customizer.withDefaults()))


Exploring Basic Authentication
- Most basic option for Securing REST API
    - BUT has many flaws
    - NOT recommended for production use
- Base 64 encoded username and password is sent as request header
    - Authorization: Basic aW4yOG1pbnV0ZXM6ZHVtbXk=
    - (DISADVANTAGE) Easy Decoding
- Basic Auth Authorization Header:
    - Does NOT contain authorization information (user access, roles,..)
    - Does NOT have Expiry Date

Getting started with Cross-Site Request Forgery (CSRF)

- How can you protect from CSRF?
- 1: Synchronizer token pattern
    - A token created for each request
    - To make an update (POST, PUT, ..), you need a CSRF token from the previous request
- 2: SameSite cookie (Set-Cookie: SameSite=Strict)
    - application.properties
        - server.servlet.session.cookie.same-site=strict
    - Depends on browser support



If we build web application using thymleaf 2.1+ version then a CSRF token will be added to all the forms

If REST API is stateless, no need to worry about CSRF, CSRF comes in to play only when a session is involved. CSRF token is tied with Session Cookie

- Browsers do NOT allow AJAX calls to resources outside current origin
- Cross-Origin Resource Sharing (CORS): Specification that allows you to configure which cross-domain requests are allowed
- Global Configuration
    - Configure addCorsMappings callback method in WebMvcConfigurer
- Local Configuration
    - @CrossOrigin - Allow from all origins
    - @CrossOrigin(origins = "https://www.in28minutes.com") - Allow from specific origin


- User credentials can be stored in:
    - In Memory - For test purposes. Not recommended for production.
    - Database - You can use JDBC/JPA to access the credentials.
    - LDAP - Lightweight Directory Access Protocol Open protocol for directory services and authentication


Encoding vs Hashing vs Encryption
- Encoding: Transform data - one form to another
    - Does NOT use a key or password
    - Is reversible
    - Typically NOT used for securing data Usecases: Compression, Streaming
    - Example: Base 64, Wav, MP3
- Hashing: Convert data into a Hash (a String)
    - One-way process
    - NOT reversible
    - You CANNOT get the original data back! Usecases: Validate integrity of data
    - Example: bcrypt, scrypt , argon2
- Encryption: Encoding data using a key or password
    - You need to key or password to decrypt
    - Example: RSA


Spring Security - Storing Passwords

- Hashes like SHA-256 are no longer secure
- Modern systems can perform billions of hash calculations a second
    - AND systems improve with time!
- Recommended: Use adaptive one way functions with Work factor of 1 second
    - It should take at least 1 second to verify a password on your system
    - Examples: bcrypt, scrypt, argon2, ..
- PasswordEncoder - interface for performing one way transformation of a password
    - (REMEMBER) Confusingly Named!
    - BCryptPasswordEncoder


Getting Started with JWT
- Basic Authentication
    - No Expiration Time
    - No User Details
    - Easily Decoded
- How about a custom token system?
    - Custom Structure
    - Possible Security Flaws
    - Service Provider & Service Consumer should understand
- JWT (Json Web Token)
    - Open, industry standard for representing claims securely between two parties
    - Can Contain User Details and Authorizations

What does a JWT contain?
- Header
    - Type: JWT
    - Hashing Algorithm: HS512
- Payload
    - Standard Attributes
        - iss: The issuer
        - sub: The subject
        - aud: The audience
        - exp: When does token expire?
        - iat: When was token issued?
    - Custom Attributes
        - youratt1: Your custom attribute 1
- Signature
    - Includes a Secret


Symmetric key encryption - same key is used for encrypt and decrypt
Asymmetric key encryption - uses different keys(public key and private key) for encrypt and decrypt - This is also called public key encryption

Best practises is to use : Asymmetric key for JWT

JWT High Level Flow

Create JWT -> send to the server -> verify Jwt

Getting Started with JWT Security Configuration

- JWT Authentication using Spring Boot’s OAuth2 Resource Server
- 1: Create Key Pair
    - We will use java.security.KeyPairGenerator
    - You can use openssl as well
- 2: Create RSA Key object using Key Pair
    - com.nimbusds.jose.jwk.RSAKey
- 3: Create JWKSource (JSON Web Key source)
    - Create JWKSet (a new JSON Web Key set) with the RSA Key
    - Create JWKSource using the JWKSet
- 4: Use RSA Public Key for Decoding
    - NimbusJwtDecoder.withPublicKey(rsaKey().toRSAPublicKey()).build()
- 5: Use JWKSource for Encoding
    - return new NimbusJwtEncoder(jwkSource());
    - We will use this later in the JWT Resource

Step 1: Use Basic Auth for getting the JWT Token Step 2-n: Use JWT token as Bearer Token for authenticating requests


Understanding Spring Security Authentication
- Authentication is done as part of the Spring Security Filter Chain!
    - 1: AuthenticationManager - Responsible for authentication
        - Can interact with multiple authentication providers
    - 2: AuthenticationProvider - Perform specific authentication type
        - JwtAuthenticationProvider - JWT Authentication
    - 3: UserDetailsService - Core interface to load user data
- How is authentication result stored?
    - SecurityContextHolder -> SecurityContext -> Authentication -> GrantedAuthority
        - Authentication - (After authentication) Holds user (Principal) details
        - GrantedAuthority - An authority granted to principal (roles, scopes,..)


- Exploring Spring Security Authorization
    - 1: Global Security: authorizeHttpRequests
        - .requestMatchers("/users").hasRole("USER")
        - hasRole, hasAuthority, hasAnyAuthority, isAuthenticated
    - 2: Method Security (@EnableMethodSecurity)
    - @Pre and @Post Annotations
        - @PreAuthorize("hasRole('USER') and #username == authentication.name")
        - @PostAuthorize("returnObject.username == 'in28minutes'")
    - JSR-250 annotations
        - @EnableMethodSecurity(jsr250Enabled = true)
        - @RolesAllowed({"ADMIN", "USER"})
    - @Secured annotation
        - @EnableMethodSecurity(securedEnabled = true)
        - @Secured({“ROLE_ADMIN", “ROLE_USER"}) 

