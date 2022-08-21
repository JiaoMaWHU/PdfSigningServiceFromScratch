import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Objects;

import org.apache.pdfbox.examples.signature.SigUtils;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

public class CreateSignatureExample extends CreateSignatureBase {
  public CreateSignatureExample(String certPath, String keyId) throws CertificateException, IOException {
    super(certPath, keyId);
  }

  public void signDetached(File file) throws IOException {
    this.signDetached(file, file, (String)null);
  }

  public void signDetached(File inFile, File outFile) throws IOException {
    this.signDetached(inFile, outFile, (String)null);
  }

  public void signDetached(File inFile, File outFile, String tsaUrl) throws IOException {
    if (inFile != null && inFile.exists()) {
      this.setTsaUrl(tsaUrl);
      FileOutputStream fos = new FileOutputStream(outFile);
      PDDocument doc = null;

      try {
        doc = PDDocument.load(inFile);
        this.signDetached((PDDocument)doc, (OutputStream)fos);
      } finally {
        IOUtils.closeQuietly(doc);
        IOUtils.closeQuietly(fos);
      }

    } else {
      throw new FileNotFoundException("Document for signing does not exist");
    }
  }

  public void signDetached(PDDocument document, OutputStream output) throws IOException {
    int accessPermissions = SigUtils.getMDPPermission(document);
    if (accessPermissions == 1) {
      throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
    } else {
      PDSignature signature = new PDSignature();
      signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
      signature.setName("Example User");
      signature.setLocation("Los Angeles, CA");
      signature.setReason("Testing");
      signature.setSignDate(Calendar.getInstance());
      if (accessPermissions == 0) {
        SigUtils.setMDPPermission(document, signature, 2);
      }

      if (this.isExternalSigning()) {
        document.addSignature(signature);
        ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(output);
        byte[] cmsSignature = this.sign(externalSigning.getContent());
        externalSigning.setSignature(cmsSignature);
      } else {
        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPreferredSignatureSize(18944);
        document.addSignature(signature, this, signatureOptions);
        document.saveIncremental(output);
      }

    }
  }

  public static void main(String[] args) throws IOException, GeneralSecurityException {
    String certPath = Objects.requireNonNull(CreateSignatureExample.class.getResource("/cert.pem")).getPath();
    String inFilePath = Objects.requireNonNull(CreateSignatureExample.class.getResource("/dummy.pdf")).getPath();
    String kmsKeyId = "arn:aws:kms:us-east-2:xxxxxxx";
    CreateSignatureExample signing = new CreateSignatureExample(certPath, kmsKeyId);
    File inFile = new File(inFilePath);
    String name = inFile.getName();
    String substring = name.substring(0, name.lastIndexOf(46));
    File outFile = new File("~/dummy_signed.pdf");
    signing.signDetached(inFile, outFile);
  }
}
