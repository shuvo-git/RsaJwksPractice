package com.jobayed.auth_service.service;


import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

@Service
public class KeyGenService {


    private final Path privateFileName = Path.of("E:\\Office\\Practice\\RsaJwksPractice\\auth_service\\certs\\private.pem");
    private final Path publicFileName  = Path.of("E:\\Office\\Practice\\RsaJwksPractice\\auth_service\\certs\\public.pem");

    private String privateKeyStr = null;
    private String publicKeyStr = null;

    private JWK jwk;

    private RSAKey rsaKey;
    private RSAPublicKey rsaPublicKey;
    private RSAPrivateKey rsaPrivateKey;



    public KeyGenService(){
        this.privateKeyStr = this.readKey(privateFileName);
        this.publicKeyStr = this.readKey(publicFileName);

        try {
            this.jwk = JWK.parseFromPEMEncodedObjects(privateKeyStr);

            this.rsaKey = jwk.toRSAKey();

            rsaPrivateKey = this.rsaKey.toRSAPrivateKey();
            rsaPublicKey = this.rsaKey.toRSAPublicKey();

        } catch (JOSEException e) {
            e.printStackTrace();
        }

    }

    private String readKey(Path fileName)
    {
        try {
            String str = Files.readString(fileName);
            return str;

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String encryptJwt(){
        // Compose the JWT claims set
        Date now = new Date();

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .issuer("https://openid.net")
                .subject("alice")
                .audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
                .expirationTime(new Date(now.getTime() + 1000*60*10)) // expires in 10 minutes
                .notBeforeTime(now)
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString())
                .build();



        // Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
        JWEHeader header = new JWEHeader(
                JWEAlgorithm.RSA_OAEP_256,
                EncryptionMethod.A128GCM
        );

        // Create the encrypted JWT object
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

        // Create an encrypter with the specified public RSA key
        RSAEncrypter encrypter = new RSAEncrypter(rsaPublicKey);

        // Do the actual encryption
        try {
            jwt.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        // Serialise to JWT compact form
        String jwtString = jwt.serialize();

        System.out.println(jwtString);
        return jwtString;

    }

    public void decryptJwt(String jwtString) throws ParseException, JOSEException{
        EncryptedJWT jwt = EncryptedJWT.parse(jwtString);
        RSADecrypter decrypter = new RSADecrypter(rsaPrivateKey);
        jwt.decrypt(decrypter);

        // Retrieve JWT claims
        System.out.println("[ISSUER] - "+jwt.getJWTClaimsSet().getIssuer());;
        System.out.println("[SUBJECT] - "+jwt.getJWTClaimsSet().getSubject());
        System.out.println("[SIZE] - "+jwt.getJWTClaimsSet().getAudience().size());
        System.out.println("[ExpirationTime] - "+jwt.getJWTClaimsSet().getExpirationTime());
        System.out.println("[NotBeforeTime] - "+jwt.getJWTClaimsSet().getNotBeforeTime());
        System.out.println("[IssueTime] - "+jwt.getJWTClaimsSet().getIssueTime());
        System.out.println("[JWT ID] - "+jwt.getJWTClaimsSet().getJWTID());
    }
}