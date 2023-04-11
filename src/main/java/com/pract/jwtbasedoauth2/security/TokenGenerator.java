package com.pract.jwtbasedoauth2.security;

import com.pract.jwtbasedoauth2.document.User;
import com.pract.jwtbasedoauth2.dto.TokenDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
public class TokenGenerator {

    @Autowired
    JwtEncoder accessTokenEncoder;

    @Autowired
    @Qualifier("jwtRefreshTokenEncoder")
    JwtEncoder refreshTokenEncoder;

    private String createAccessToken(Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        Instant now = Instant.now();

        JwtClaimsSet claimsSet = JwtClaimsSet.builder().
                issuer("myApp")
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.DAYS))
                .subject(user.getId())
                .build();
        return accessTokenEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }
    private String createRefreshToken(Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        Instant now = Instant.now();

        JwtClaimsSet claimsSet = JwtClaimsSet.builder().
                issuer("myApp")
                .issuedAt(now)
                .expiresAt(now.plus(30, ChronoUnit.DAYS))
                .subject(user.getId())
                .build();
        return refreshTokenEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }

    public TokenDto createToken(Authentication authentication) {
        if (!(authentication.getPrincipal() instanceof User user)) {
            throw new BadCredentialsException(MessageFormat.format(
                    "principal {0} is not of User type", authentication.getPrincipal().getClass()));
        }
        TokenDto tokenDto = new TokenDto();
        tokenDto.setUserId(user.getId());
        tokenDto.setAccessToken(createAccessToken(authentication));

        String refrshToken;
        if (authentication.getCredentials() instanceof Jwt jwt) {
            Instant now = Instant.now();
            Instant expireAt = jwt.getExpiresAt();
            Duration duration = Duration.between(now, expireAt);
            Long daysUntilExpired = duration.toDays();
            if (daysUntilExpired < 7) {
                refrshToken = createRefreshToken(authentication);
            } else {
                refrshToken = jwt.getTokenValue();
            }
        } else {
            refrshToken = createRefreshToken(authentication);
        }
        tokenDto.setRefreshToken(refrshToken);
        return tokenDto;
    }
}
