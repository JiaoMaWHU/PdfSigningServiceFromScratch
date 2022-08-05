import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedData;

class CMSProcessableInputStream implements CMSTypedData {
  private InputStream in;
  private final ASN1ObjectIdentifier contentType;

  CMSProcessableInputStream(InputStream is) {
    this(new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()), is);
  }

  CMSProcessableInputStream(ASN1ObjectIdentifier type, InputStream is) {
    this.contentType = type;
    this.in = is;
  }

  public Object getContent() {
    return this.in;
  }

  public void write(OutputStream out) throws IOException, CMSException {
    IOUtils.copy(this.in, out);
    this.in.close();
  }

  public ASN1ObjectIdentifier getContentType() {
    return this.contentType;
  }
}