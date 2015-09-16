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

import java.io.File;
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
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.math.RandomUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Connector for communication with a local KeePass with installed KeePassHttp-Plugin. By default the key and id will be
 * stored after successfull association.
 *
 * @author Ralf Seidengarn
 */
public class KeePassHttpConnector {

   private static final Log LOG = LogFactory.getLog(KeePassHttpConnector.class);
   private int port = 19455;
   private File keyFile;
   private String id;
   private String key;

   /**
    * Constructor tries to load the stored key and id
    */
   public KeePassHttpConnector() {
      this.keyFile = new File(FileUtils.getUserDirectory(), "keepasshttpclient.json");
      loadKey();
   }

   /**
    * Constructor
    * 
    * @param port port running KeePassHttp-Plugin (if different from default)
    */
   public KeePassHttpConnector(int port) {
      this();
      this.port = port;
   }

   /**
    * Constructor with a predefined id an key, both will not be stored
    * 
    * @param id Identifier for the client authenticated by the key as configured in the KeepassDatabase
    * @param key AES-Key
    */
   public KeePassHttpConnector(String id, String key) {
      this.id = id;
      this.key = key;
      this.keyFile = null;
   }

   /**
    * Gets a list of logins available for the specified URL
    * 
    * @param url URL to search for in the KeePassDatabase, by default this can also be the name of the entry in KDB
    * @param submitUrl optional URL
    * @return a List of KeePassLogin with 0 elements if no matching login was found
    * @throws KeePassHttpException exception during communication
    */
   @SuppressWarnings("unchecked")
   public List<KeePassLogin> getLogins(String url, String submitUrl) throws KeePassHttpException {
      try {
         try {
            testAssociate();
         } catch (KeePassHttpNotAssociatedException e) {
            LOG.info("KeePass is not associated, try to associate");
            associate();
         }

         if (url == null) {
            throw new KeePassHttpException("missing parameter url");
         }
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
            throw new KeePassHttpCommunicationException("Communication with KeePass failed, http-returncode is "
                                                        + result + ", expected 200");
         }

         String responseBody = postMethod.getResponseBodyAsString();
         map = (Map<String, Object>) JSONParser.parse(responseBody);

         if (map == null || map.get("Success") == null) {
            throw new KeePassHttpCommunicationException(
                     "Communication with KeePass failed, response from KeePassHttp is invalid");
         }

         if (!map.get("Success").equals("true")) {
            throw new KeePassHttpCommunicationException(
                     "Communication with KeePass failed, call of get-logins with no success (access may be declined by user)");
         }

         iv = (String) map.get("Nonce");
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
         throw new KeePassHttpCommunicationException("Communication with KeePass failed", e);
      } catch (IOException e) {
         throw new KeePassHttpCommunicationException("Communication with KeePass failed", e);
      }
   }

   /**
    * Load the key (and id) from the filesystem
    */
   @SuppressWarnings("unchecked")
   private void loadKey() {
      if (keyFile != null) {
         try {
            String data = FileUtils.readFileToString(keyFile);
            Map<String, Object> map = (Map<String, Object>) JSONParser.parse(data);
            id = (String) map.get("Id");
            key = (String) map.get("Key");
         } catch (IOException e) {
            LOG.error("key could not be loaded");
         }
      }
   }

   /**
    * Stores the key (and id) in the filesystem
    * 
    * @throws KeePassHttpException
    */
   private void storeKey() throws KeePassHttpException {
      if (keyFile != null) {
         try {
            Map<String, Object> map = new HashMap<String, Object>();
            map.put("Key", key);
            map.put("Id", id);
            String data = JSONParser.compose(map);

            FileUtils.writeStringToFile(keyFile, data);
         } catch (IOException e) {
            throw new KeePassHttpException("Exception while storing the key to communicate with KeePass", e);
         }
      }
   }

   @SuppressWarnings("unchecked")
   void testAssociate() throws KeePassHttpException {
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
            throw new KeePassHttpCommunicationException("Communication with KeePass failed, http-returncode is "
                                                        + result + ", expected 200");
         }

         String responseBody = postMethod.getResponseBodyAsString();
         map = (Map<String, Object>) JSONParser.parse(responseBody);

         if (map == null || map.get("Success") == null) {
            throw new KeePassHttpCommunicationException(
                     "Communication with KeePass failed, response from KeePassHttp is invalid");
         }

         if (!map.get("Success").equals("true")) {
            throw new KeePassHttpNotAssociatedException(
                     "Communication with KeePass failed, client is not associated with KeePassHttp");
         }
      } catch (EncryptionException e) {
         throw new KeePassHttpCommunicationException("Communication with KeePass failed", e);
      } catch (IOException e) {
         throw new KeePassHttpCommunicationException("Communication with KeePass failed", e);
      }
   }

   private String generateIv() {
      byte[] ivArr = new byte[16];
      for (int i = 0; i < ivArr.length; i++) {
         ivArr[i] = (byte) RandomUtils.nextInt();
      }
      return Base64.getEncoder().encodeToString(ivArr);
   }

   @SuppressWarnings("unchecked")
   void associate() throws KeePassHttpException {
      if (key == null) {
         key = generateIv();
      }

      try {
         String iv = generateIv();
         String verifier = Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(iv, iv, key));

         Map<String, Object> map = new HashMap<String, Object>();
         map.put("RequestType", "associate");
         map.put("Key", key);
         map.put("Nonce", iv);
         map.put("Verifier", verifier);
         HttpClient client = new HttpClient();
         client.getHttpConnectionManager().getParams().setSoTimeout(10000);
         PostMethod postMethod = new PostMethod("http://localhost:" + port);
         RequestEntity requestEntity = new StringRequestEntity(JSONParser.compose(map), "text/xml", "UTF-8");
         postMethod.setRequestEntity(requestEntity);
         int result = client.executeMethod(postMethod);
         if (result != 200) {
            throw new KeePassHttpCommunicationException("Communication with KeePass failed, http-returncode is "
                                                        + result + ", expected 200");
         }

         String responseBody = postMethod.getResponseBodyAsString();
         map = (Map<String, Object>) JSONParser.parse(responseBody);

         if (map == null || map.get("Success") == null) {
            throw new KeePassHttpCommunicationException(
                     "Communication with KeePass failed, response from KeePassHttp is invalid");
         }

         if (!map.get("Success").equals("true")) {
            throw new KeePassHttpNotAssociatedException(
                     "Communication with KeePass failed, client could not associate with KeePassHttp, maybe declined by user");
         }

         id = (String) map.get("Id");
         storeKey();
      } catch (EncryptionException e) {
         throw new KeePassHttpCommunicationException("Communication with KeePass failed", e);
      } catch (IOException e) {
         throw new KeePassHttpCommunicationException("Communication with KeePass failed", e);
      }
   }
}
