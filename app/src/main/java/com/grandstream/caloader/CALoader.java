package com.grandstream.caloader;


import android.util.Log;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import android.net.http.SslCertificate;



public class CALoader {

    private static final String TAG = "CALoader";

    static void load_system_ca(){
        X509TrustManager tm = systemDefaultTrustManager();

        X509Certificate[] certificates = tm.getAcceptedIssuers();

        for(X509Certificate cert:certificates){
            SslCertificate sslCert = new SslCertificate(cert);
            Log.d(TAG,"being cert dump------");
            Log.d(TAG,"cert cn:" + sslCert.getIssuedTo().getCName());
            Log.d(TAG,"cert o:" + sslCert.getIssuedTo().getOName());
            Log.d(TAG,"cert ou:" + sslCert.getIssuedTo().getUName());
            Log.d(TAG,"end cert dump------");
        }
    }


    static private X509TrustManager systemDefaultTrustManager() {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
                throw new IllegalStateException("Unexpected default trust managers:"
                        + Arrays.toString(trustManagers));
            }
            return (X509TrustManager) trustManagers[0];
        } catch (GeneralSecurityException e) {
            throw new AssertionError(); // The system has no TLS. Just give up.
        }
    }




}
