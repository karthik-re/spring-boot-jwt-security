package org.example.authentication.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JWTGenerator {

    private static final SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    public String generateToken(Authentication authentication) {
        String username = authentication.getName();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + SecurityConstants.EXPIRATION_TIME);

        String token = Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(expiryDate)
                .signWith(key)
                .compact();

        System.out.println("Token generated: " + token);

        return token;
    }

    public String getUsernameFromToken(String token) {

        Claims claims = (Claims) Jwts.parser()
                .verifyWith(key)
                .build()
                .parse(token)
                .getPayload();

        return claims.getSubject();

    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parse(token);
            return true;
        } catch (Exception e) {
            throw new AuthenticationCredentialsNotFoundException("Expired or invalid JWT token");
        }
    }


}
