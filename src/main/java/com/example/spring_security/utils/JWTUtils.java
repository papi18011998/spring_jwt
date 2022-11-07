package com.example.spring_security.utils;

public class JWTUtils {
    public static final String SECRET = "youssfiSecret";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String AUTHORIZATION_PREFIX = "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN = 120000;
    public static final long EXPIRE_REFRESH_TOKEN = 1000000;
}
