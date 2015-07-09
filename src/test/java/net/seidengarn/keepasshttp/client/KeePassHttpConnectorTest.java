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

import static org.junit.Assert.assertEquals;
import net.seidengarn.keepasshttp.client.exception.KeePassHttpException;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.Cipher;

import org.junit.Test;

public class KeePassHttpConnectorTest {

   private String id = "Test Key 128bit";
   private String key = "QVFJREJBVUdCd2dKQ2dzTQ==";

   public KeePassHttpConnectorTest() {
      try {
         if (Cipher.getMaxAllowedKeyLength("AES") > 128) {
            id = "Test Key";
            key = "Lgh8xMEkV2j10bG7O42GjCibsUEpM80T7Db+skKGiNc=";
         }
      } catch (NoSuchAlgorithmException e) {
      }
   }

   @Test
   public void testGetLoginsEmpty() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);

      List<KeePassLogin> logins = connector.getLogins("http://www.doesnotexist.com/", null);
      assertEquals(0, logins.size());
   }

   @Test
   public void testGetLoginsMatchPartialTitle() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);

      List<KeePassLogin> logins = connector.getLogins("http://www.google.com/", null);
      assertEquals(1, logins.size());
      assertEquals("google-user", logins.get(0).getLogin());
   }

   @Test
   public void testGetLoginsMatchExactTitle() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);

      List<KeePassLogin> logins = connector.getLogins("http://www.yahoo.com/", null);
      assertEquals(1, logins.size());
      assertEquals("www.yahoo-user", logins.get(0).getLogin());
   }

   @Test
   public void testGetLoginsMatchPartialTitleYahoo() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);
      List<KeePassLogin> logins = connector.getLogins("http://yahoo.com/", null);
      assertEquals(1, logins.size());
      assertEquals("yahoo-user", logins.get(0).getLogin());
   }

   @Test
   public void testGetLoginsMatchHostURLField() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);
      List<KeePassLogin> logins = connector.getLogins("http://citi.com/", null);
      assertEquals(1, logins.size());
      assertEquals("citi-user", logins.get(0).getLogin());
   }

   @Test
   public void testGetLoginsMatchRealURLField() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);
      List<KeePassLogin> logins = connector.getLogins("http://citi1.com/", null);
      assertEquals(1, logins.size());
      assertEquals("citi1-user", logins.get(0).getLogin());
   }

   @Test
   public void testGetLoginsMatchTitleAndURLField() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);
      List<KeePassLogin> logins = connector.getLogins("https://cititest.com/", null);
      assertEquals(1, logins.size());
      assertEquals("cititest-user", logins.get(0).getLogin());
   }

   @Test
   public void testGetLoginsMatchTitleURLTitleMismatch() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);
      List<KeePassLogin> logins = connector.getLogins("https://bogustest.com/", null);
      assertEquals(1, logins.size());
      assertEquals("bogustest-user", logins.get(0).getLogin());
   }

   @Test
   public void testGetLoginsMatchURLURLTitleMisMatch() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);
      List<KeePassLogin> logins = connector.getLogins("https://www.bogustest.com/", null);
      assertEquals(1, logins.size());
      assertEquals("bogustest-user", logins.get(0).getLogin());
   }

   @Test
   public void testGetLoginsMatchTitleURLTitleMismatch2() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);
      List<KeePassLogin> logins = connector.getLogins("https://bogustest1.com/", null);
      assertEquals(1, logins.size());
      assertEquals("bogustest1-user", logins.get(0).getLogin());
   }

   @Test
   public void testGetLoginsMatchURLURLTitleMismatch2() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);
      List<KeePassLogin> logins = connector.getLogins("https://www.bogustest1.com/", null);
      assertEquals(1, logins.size());
      assertEquals("bogustest1-user", logins.get(0).getLogin());
   }

   @Test
   public void testGetLoginsSubpath() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);
      List<KeePassLogin> logins = connector.getLogins("http://www.host.com", "http://www.host.com/path1");
      assertEquals(1, logins.size());
      assertEquals("user1", logins.get(0).getLogin());
   }

   // test(function get_logins_subpath() {
   // var resp;
   // get_logins("http://www.host.com", "http://www.host.com/path1", null, function(r) {
   // resp = r;
   // lock.notify();
   // });
   // lock.wait();
   // var response = JSON.parse(resp);
   // assert_equals(1, response.Entries.length);
   // assert_equals("user1", decrypt(response.Entries[0].Login, response.Nonce));
   // });
   @Test
   public void testGetLoginsSubpath2() throws KeePassHttpException {
      KeePassHttpConnector connector = new KeePassHttpConnector(id, key);
      List<KeePassLogin> logins = connector.getLogins("http://www.host.com",
               "http://www.host.com/path2?param=value");
      assertEquals(1, logins.size());
      assertEquals("user2", logins.get(0).getLogin());
   }
   // test(function get_logins_subpath_2() {
   // var resp;
   // get_logins("http://www.host.com", "http://www.host.com/path2?param=value", null, function(r) {
   // resp = r;
   // lock.notify();
   // });
   // lock.wait();
   // var response = JSON.parse(resp);
   // assert_equals(1, response.Entries.length);
   // assert_equals("user2", decrypt(response.Entries[0].Login, response.Nonce));
   // });
}
