import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import org.apache.pdfbox.examples.signature.SigUtils;
import org.apache.pdfbox.examples.signature.ValidationTimeStamp;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public abstract class CreateSignatureBase implements SignatureInterface {
  private PrivateKey privateKey;
  private Certificate[] certificateChain;
  private String tsaUrl;
  private boolean externalSigning;

  public CreateSignatureBase(KeyStore keystore, char[] pin) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException {
    Enumeration<String> aliases = keystore.aliases();
    Certificate cert = null;

    while(cert == null && aliases.hasMoreElements()) {
      String alias = (String)aliases.nextElement();
      this.setPrivateKey((PrivateKey)keystore.getKey(alias, pin));
      Certificate[] certChain = keystore.getCertificateChain(alias);
      if (certChain != null) {
        this.setCertificateChain(certChain);
        cert = certChain[0];
        if (cert instanceof X509Certificate) {
          ((X509Certificate)cert).checkValidity();
          SigUtils.checkCertificateUsage((X509Certificate)cert);
        }
      }
    }

    if (cert == null) {
      throw new IOException("Could not find certificate");
    }
  }

  public final void setPrivateKey(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public final void setCertificateChain(Certificate[] certificateChain) {
    this.certificateChain = certificateChain;
  }

  public Certificate[] getCertificateChain() {
    return this.certificateChain;
  }

  public void setTsaUrl(String tsaUrl) {
    this.tsaUrl = tsaUrl;
  }

  public byte[] sign(InputStream content) throws IOException {
    try {
      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
      X509Certificate cert = (X509Certificate)this.certificateChain[0];
      ContentSigner sha1Signer = new AWSKMSContentSigner();
      gen.addSignerInfoGenerator((new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder()).build())).build(sha1Signer, cert));
      gen.addCertificates(new JcaCertStore(Arrays.asList(this.certificateChain)));
      CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
      CMSSignedData signedData = gen.generate(msg, false);
      if (this.tsaUrl != null && this.tsaUrl.length() > 0) {
        ValidationTimeStamp validation = new ValidationTimeStamp(this.tsaUrl);
        signedData = validation.addSignedTimeStamp(signedData);
      }

      return signedData.getEncoded();
    } catch (GeneralSecurityException var8) {
      throw new IOException(var8);
    } catch (CMSException var9) {
      throw new IOException(var9);
    } catch (OperatorCreationException var10) {
      throw new IOException(var10);
    }
  }

  public void setExternalSigning(boolean externalSigning) {
    this.externalSigning = externalSigning;
  }

  public boolean isExternalSigning() {
    return this.externalSigning;
  }
}
