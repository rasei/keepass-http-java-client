/*
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

import net.seidengarn.json.JSONParser;
import net.seidengarn.keepasshttp.client.exception.EncryptionException;
import net.seidengarn.keepasshttp.client.exception.KeePassHttpCommunicationException;
import net.seidengarn.keepasshttp.client.exception.KeePassHttpException;
import net.seidengarn.keepasshttp.client.exception.KeePassHttpNotAssociatedException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;

/**
 * Connector for communication with a local KeePass with installed KeePassHttp-Plugin.
 *
 * @author Ralf Seidengarn
 * @version $Revision$
 */
public class KeePassHttpConnector {

   private int port;
   private String id;
   private String key;

   public KeePassHttpConnector() {
      this(19455);
   }

   public KeePassHttpConnector(int port) {
      this.port = port;
   }

   public KeePassHttpConnector(String id, String key) {
      this();
      this.id = id;
      this.key = key;
   }

   public List<KeePassLogin> getLogins(String url, String submitUrl) throws KeePassHttpException {
      try {
         testAssociate();

         // TODO url!=null
         if (submitUrl == null) {
            submitUrl = url;
         }

         HttpClient client = new HttpClient();
         client.getHttpConnectionManager().getParams().setSoTimeout(10000);

         String iv = generateIv();

         Map<String, Object> map = new HashMap<>();
         map.put("RequestType", "get-logins");
         map.put("Id", id);
         map.put("Nonce", iv);
         map.put("Verifier", Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(iv, iv, key)));
         map.put("Url", Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(url, iv, key)));
         map.put("SubmitUrl", Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(submitUrl, iv, key)));
         String request = JSONParser.compose(map);

         PostMethod postMethod = new PostMethod("http://localhost:" + port);
         RequestEntity requestEntity = new StringRequestEntity(request, "text/xml", "UTF-8");
         postMethod.setRequestEntity(requestEntity);
         int result = client.executeMethod(postMethod);
         if (result != 200) {
            throw new KeePassHttpCommunicationException("http-returncode is " + result + ", expected 200");
         }

         String responseBody = postMethod.getResponseBodyAsString();
         map = (Map<String, Object>) JSONParser.parse(responseBody);

         if (map == null || map.get("Success") == null) {
            throw new KeePassHttpCommunicationException("response from KeePassHttp is invalid");
         }

         if (!map.get("Success").equals("true")) {
            throw new KeePassHttpCommunicationException(
                     "call of get-logins with no success (access may be declined by user)");
         }

         iv = (String) map.get("Nonce");
         // assertNotNull(map.get("Entries")); // TODO
         // assertTrue(map.get("Entries") instanceof List);// TODO
         List<KeePassLogin> loginList = new ArrayList<>();

         List<Object> entries = (List<Object>) map.get("Entries");
         for (Object entryObject : entries) {
            Map<String, Object> entryMap = (Map<String, Object>) entryObject;

            KeePassLogin login = new KeePassLogin();
            login.setName(EncryptionUtil.decrypt(Base64.getDecoder().decode((String) entryMap.get("Name")), iv,
                     key));
            login.setLogin(EncryptionUtil.decrypt(Base64.getDecoder().decode((String) entryMap.get("Login")), iv,
                     key));
            login.setPassword(EncryptionUtil.decrypt(
                     Base64.getDecoder().decode((String) entryMap.get("Password")), iv, key));

            loginList.add(login);
         }

         return loginList;
      } catch (EncryptionException e) {
         throw new KeePassHttpCommunicationException(e);
      } catch (IOException e) {
         throw new KeePassHttpCommunicationException(e);
      }
   }

   private void testAssociate() throws KeePassHttpException {
      if (id == null || key == null) {
         associate();
      }

      try {
         String iv = generateIv();
         String verifier = Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(iv, iv, key));

         Map<String, Object> map = new HashMap<String, Object>();
         map.put("RequestType", "test-associate");
         map.put("Id", id);
         map.put("Nonce", iv);
         map.put("Verifier", verifier);
         HttpClient client = new HttpClient();
         client.getHttpConnectionManager().getParams().setSoTimeout(10000);
         PostMethod postMethod = new PostMethod("http://localhost:" + port);
         RequestEntity requestEntity = new StringRequestEntity(JSONParser.compose(map), "text/xml", "UTF-8");
         postMethod.setRequestEntity(requestEntity);
         int result = client.executeMethod(postMethod);
         if (result != 200) {
            throw new KeePassHttpCommunicationException("http-returncode is " + result + ", expected 200");
         }

         String responseBody = postMethod.getResponseBodyAsString();
         map = (Map<String, Object>) JSONParser.parse(responseBody);

         if (map == null || map.get("Success") == null) {
            throw new KeePassHttpCommunicationException("response from KeePassHttp is invalid");
         }

         if (!map.get("Success").equals("true")) {
            throw new KeePassHttpNotAssociatedException("client is not associated with KeePassHttp");
         }
      } catch (EncryptionException e) {
         throw new KeePassHttpCommunicationException(e);
      } catch (IOException e) {
         throw new KeePassHttpCommunicationException(e);
      }
   }

   private String generateIv() {
      // TODO implement
      return "QVFJREJBVUdCd2dKQ2dzTQ==";
   }

   private void associate() {
      // TODO Auto-generated method stub

   }

}
