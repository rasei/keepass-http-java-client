/**
 * Copyright 2015 Ralf Seidengarn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 */
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

      String ivEncrypted = EncryptionUtil.decrypt(Base64.getDecoder().decode(verifier), iv, key);
      assertEquals(iv, ivEncrypted);
   }

}
