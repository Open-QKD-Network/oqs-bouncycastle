package com.goodstartsoft.pqc;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;

public class KeyStoreUtils
{
    /**
     * Create a private key with an associated self-signed certificate
     * returning them wrapped in an X500PrivateCredential
     *
     * Note: We use generateECKeyPair() from chapter6.EcDsaUtils and
     * createTrustAnchor() from chapter8.JcaX509Certificate.
     *
     * @return an X500PrivateCredential containing the key and its certificate.
     */
    public static PrivateCredential createSelfSignedCredentials(int keylength)
        throws GeneralSecurityException, OperatorCreationException
    {
        JcaX509CertificateConverter certConverter =
                           new JcaX509CertificateConverter().setProvider("BC");

        KeyPair selfSignedKp = null;
        if (keylength == 256)
            selfSignedKp = EcDsaUtils.generateECKeyPair("P-256");
        if (keylength == 512)
            selfSignedKp = EcDsaUtils.generateECKeyPair("P-521");

        X509CertificateHolder selfSignedHldr = null;
        if (keylength == 256)
            selfSignedHldr =
                        JcaX509Certificate.createTrustAnchor(selfSignedKp, "SHA256withECDSA");
        if (keylength == 512)
            selfSignedHldr =
                       JcaX509Certificate.createTrustAnchor(selfSignedKp, "SHA512withECDSA");

        X509Certificate selfSignedCert = certConverter.getCertificate(selfSignedHldr);

        return new PrivateCredential(selfSignedCert, selfSignedKp.getPrivate());
    }
}