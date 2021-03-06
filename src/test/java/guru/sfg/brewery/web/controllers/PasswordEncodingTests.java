package guru.sfg.brewery.web.controllers;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.util.DigestUtils;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Disabled
public class PasswordEncodingTests {

    static final String PASSWORD="password";


    @Test
    void hashingExample() {
        System.out.println(
                DigestUtils.md5DigestAsHex(PASSWORD.getBytes()
                ));
    }

    @Test
    void testNoOps(){
        PasswordEncoder noOps= NoOpPasswordEncoder.getInstance();
        System.out.println(noOps.encode(PASSWORD));
    }

    @Test
    void testLdap() {
        PasswordEncoder ldap=new LdapShaPasswordEncoder();
        System.out.println(ldap.encode(PASSWORD));
        System.out.println(ldap.encode("tiger"));

        String encodedLdap=ldap.encode(PASSWORD);
        assertTrue(ldap.matches(PASSWORD,encodedLdap))  ;
    }

    @Test
    void testSHA256() {
        PasswordEncoder sha256=new StandardPasswordEncoder() ;
        System.out.println(sha256.encode(PASSWORD));
        System.out.println(sha256.encode(PASSWORD)); 
    }

    @Test
    void testBcrypt() {
        PasswordEncoder bcrypt=new BCryptPasswordEncoder();
        System.out.println(bcrypt.encode(PASSWORD));
        System.out.println(bcrypt.encode(PASSWORD));
        System.out.println(bcrypt.encode("jana123"));

    }


    @Test
    void testBcrypt15() {
        PasswordEncoder bcrypt15= new BCryptPasswordEncoder(15) ;
        System.out.println("bcrypt15 : "+bcrypt15.encode("tiger"));
    }
}
