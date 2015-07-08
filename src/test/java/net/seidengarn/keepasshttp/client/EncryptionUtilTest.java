package net.seidengarn.keepasshttp.client;

import static org.junit.Assert.assertEquals;

import java.util.Base64;

import org.junit.Test;

public class EncryptionUtilTest {

   @Test
   public void test128BitKeys() throws Exception {
      String key = "QTdjaFJFUnE4b0dJazJtWA==";
      String iv = "QVFJREJBVUdCd2dKQ2dzTQ==";

      String verifier = Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(iv, iv, key));
      assertEquals("rn/cRWFibbGI+JmKaGgvPRGCEZrN/ixmvD4oCAnBRec=", verifier);

      String ivEncrypted = EncryptionUtil.decrypt(verifier.getBytes("UTF-8"), iv, key);
      assertEquals(iv, ivEncrypted);
   }

}
