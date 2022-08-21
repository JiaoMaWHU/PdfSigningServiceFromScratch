import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;


public class AWSKMSContentSigner implements ContentSigner {

  private final String keyId;

  public AWSKMSContentSigner (String keyId) {
    this.keyId = keyId;
  }

  private final ByteArrayOutputStream _outputStream = new ByteArrayOutputStream();

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
  }

  @Override
  public OutputStream getOutputStream() {
    return _outputStream;
  }

  @Override
  public byte[] getSignature() {
    SignRequest request = new SignRequest();
    request.setSigningAlgorithm("RSASSA_PKCS1_V1_5_SHA_256");
    request.setKeyId(keyId);
    request.setMessage(ByteBuffer.wrap(_outputStream.toByteArray()));

    AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
    SignResult result = kmsClient.sign(request);

    ByteBuffer bb = result.getSignature();
    byte[] signature = new byte[bb.remaining()];
    bb.get(signature);

    return signature;
  }
}
