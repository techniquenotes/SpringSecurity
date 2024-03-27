package com.example.springsecurity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

        @Value("${security.jwt.secret-key}")
        private String secretKey;

        @Value("${security.jwt.expiration-time}")
        private long jwtExpiration;

        //从token中获取用户名
        public String extractUsername(String token) {
            return extractClaim(token, Claims::getSubject);
        }

        //从 JWT 中提取指定声明
        public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
            final Claims claims = extractAllClaims(token); //获取 JWT 令牌中的所有声明信息
            return claimsResolver.apply(claims);  //通过 claimsResolver 函数式接口，将 claims 中的声明信息转换为指定类型 T 的数据
        }

        public String generateToken(UserDetails userDetails) {
            return generateToken(new HashMap<>(), userDetails);
        }

        //生成带有额外声明的 JWT
        public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
            return buildToken(extraClaims, userDetails, jwtExpiration);
        }

        //获取 JWT 的过期时间
        public long getExpirationTime() {
            return jwtExpiration;
        }

        private String buildToken(
                Map<String, Object> extraClaims,
                UserDetails userDetails,
                long expiration
        ) {
            return Jwts
                    .builder()
                    .setClaims(extraClaims)
                    .setSubject(userDetails.getUsername()) //Token中有Username信息
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + expiration))
                    .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                    .compact();
        }

        //验证 JWT 是否有效
        public boolean isTokenValid(String token, UserDetails userDetails) {
            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        }

        //检查 JWT 是否过期
        private boolean isTokenExpired(String token) {
            return extractExpiration(token).before(new Date());
        }

        //从 JWT 中提取过期时间
        private Date extractExpiration(String token) {
            return extractClaim(token, Claims::getExpiration);
        }

        //从 JWT 中提取所有声明
        private Claims extractAllClaims(String token) {
            return Jwts
                    .parserBuilder() //创建一个新的 JWT 解析器构建器
                    .setSigningKey(getSignInKey())  //设置 JWT 解析器使用的签名密钥
                    .build()  //构建 JWT 解析器
                    .parseClaimsJws(token) //解析传入的 JWT 令牌，该令牌包含了加密的声明
                    .getBody();  //从解析后的 JWT 中获取所有声明（Claims），并返回
        }

        private Key getSignInKey() {
            byte[] keyBytes = Decoders.BASE64.decode(secretKey);
            return Keys.hmacShaKeyFor(keyBytes);
        }
}

