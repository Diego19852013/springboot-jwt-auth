package com.diegoveliz.auth_api_jwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    private final String SECRET_KEY =
            "my_super_secret_key_that_is_at_least_32_characters_long";
//genera la llave para firmar el token
    private Key getSignInKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    // GENERAR TOKEN
    public String generateToken(String username) {
        return Jwts.builder()   //crea el token
                .setSubject(username)  //establece el usuario
                .setIssuedAt(new Date())  //establece la fecha de emision
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hora
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)  //firma el token
                .compact(); //compacta el token
    }

    // EXTRAER USERNAME(usuario)
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    // VALIDAR TOKEN
    public boolean isTokenValid(String token, String username) { //valida el token
        final String extractedUsername = extractUsername(token); //extrae el usuario
        return (extractedUsername.equals(username) && !isTokenExpired(token)); //compara el usuario y la fecha de expiracion
    }

    // VERIFICAR EXPIRACIÓN
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }

    // EXTRAER CLAIMS
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}