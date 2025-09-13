package com.hansjoerg.coloringbook.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.hansjoerg.coloringbook.config.AppProperties;
import com.hansjoerg.coloringbook.payload.ApiResponse;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingFilter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final Cache<String, Bucket> loginBuckets;
    private final Cache<String, Bucket> signupBuckets;

    private final double loginRps;
    private final double signupRps;
    private final long cacheExpiryMinutes;
    private final MessageSource messageSource;

    public RateLimitingFilter(AppProperties appProperties, MessageSource messageSource) {
        this.loginRps = appProperties.getRateLimit().getLoginRps();
        this.signupRps = appProperties.getRateLimit().getSignupRps();
        this.cacheExpiryMinutes = appProperties.getRateLimit().getCacheExpiryMinutes();
        long maxCacheSize = appProperties.getRateLimit().getMaxCacheSize();
        this.messageSource = messageSource;

        this.loginBuckets = Caffeine.newBuilder()
                .expireAfterAccess(cacheExpiryMinutes, TimeUnit.MINUTES)
                .maximumSize(maxCacheSize)
                .build();

        this.signupBuckets = Caffeine.newBuilder()
                .expireAfterAccess(cacheExpiryMinutes, TimeUnit.MINUTES)
                .maximumSize(maxCacheSize)
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String requestURI = request.getRequestURI();
        String clientIp = getClientIp(request);

        if (requestURI.equals("/auth/login")) {
            Bucket bucket = loginBuckets.get(clientIp, k -> createNewBucket(loginRps));
            if (!bucket.tryConsume(1)) {
                logger.warn("Rate limit exceeded for login from IP: {}", clientIp);
                String localizedMessage = messageSource.getMessage("error.tooManyRequests", null, LocaleContextHolder.getLocale());
                sendTooManyRequestsResponse(response, localizedMessage);
                return;
            }
        } else if (requestURI.equals("/auth/signup")) {
            Bucket bucket = signupBuckets.get(clientIp, k -> createNewBucket(signupRps));
            if (!bucket.tryConsume(1)) {
                logger.warn("Rate limit exceeded for signup from IP: {}", clientIp);
                String localizedMessage = messageSource.getMessage("error.tooManyRequests", null, LocaleContextHolder.getLocale());
                sendTooManyRequestsResponse(response, localizedMessage);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private Bucket createNewBucket(double requestsPerSecond) {
        Bandwidth limit = Bandwidth.simple((long) requestsPerSecond, Duration.ofSeconds(1));
        return Bucket4j.builder().addLimit(limit).build();
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || !xfHeader.contains(".")) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    private void sendTooManyRequestsResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        String errorJson = objectMapper.writeValueAsString(new ApiResponse(false, message));
        response.getWriter().write(errorJson);
        response.getWriter().flush();
    }
}
