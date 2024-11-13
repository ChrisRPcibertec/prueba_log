package com.back.pid_grupo01.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	private static final String SECRET_KEY="586E3272357538782F413F4428472B4B6250655368566B597033733676397924";

    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }

    // Acá se construye el token con el username(correo) y los claims de haber alguno
    private String getToken(Map<String,Object> extraClaims, UserDetails user) {
        return Jwts
            .builder()
            .setClaims(extraClaims)
            .setSubject(user.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
            .signWith(getKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    private Key getKey() {
       byte[] keyBytes=Decoders.BASE64.decode(SECRET_KEY);
       return Keys.hmacShaKeyFor(keyBytes);
    }

    //Método para sacar el username(email) del Token
    public String getUsernameFromToken(String token) {
        return getClaim(token, Claims::getSubject);
    }

    //Es boleano por lo que retorna un true o false
    public boolean isTokenValid(String token, UserDetails userDetails) {
    	
        final String username=getUsernameFromToken(token); //obtiene el username del token
        
        return (username.equals(userDetails.getUsername())&& !isTokenExpired(token)); //si no está espirado y hay username
    }

    
    /*
     public boolean isTokenValid(String token, UserDetails userDetails) {
     
	    // Obtiene el nombre de usuario desde el token
	    String usernameInToken = getUsernameFromToken(token);
	
	    // Verifica si el nombre de usuario coincide
	    if (!usernameInToken.equals(userDetails.getUsername())) {
	    
	        // Si el nombre de usuario no coincide, el token no es válido
	        return false;
	    }
	
	    // Verifica si el token ha expirado
	    if (isTokenExpired(token)) {
	    
	        // Si el token ha expirado, no es válido
	        return false;
	    }
	
	    // Si el nombre de usuario coincide y el token no ha expirado, el token es válido
	    return true;
	}

     */
    

    
    private Claims getAllClaims(String token)
    {
        return Jwts
            .parserBuilder()
            .setSigningKey(getKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    public <T> T getClaim(String token, Function<Claims,T> claimsResolver)
    {
        final Claims claims=getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Date getExpiration(String token)
    {
        return getClaim(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token)
    {
        return getExpiration(token).before(new Date());
    }
}
