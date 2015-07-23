# Java-Client for KeePassHttp
Library for accessing a KeePass-database with the [KeePassHttp](https://github.com/pfn/keepasshttp/)-Plugin

##Usage
###Prerequisites
* Install KeePass with the [KeePassHttp](https://github.com/pfn/keepasshttp/)-Plugin

	KeePassHttpConnector connector = new KeePassHttpConnector();
	List<KeePassLogin> logins = connector.getLogins("http://www.example.com/", "http://www.example.com/somewhere.html");
	for (KeePassLogin login : logins) {
		System.out.println("name: " + login.getName() + ", login: " + login.getLogin() + ", password: "
									+ login.getPassword());
	}
	
##How to run the tests
The tests are based on the tests provided by [KeePassHttp](https://github.com/pfn/keepasshttp/)-Plugin.

* Install KeePass with the [KeePassHttp](https://github.com/pfn/keepasshttp/)-Plugin
* Download and open the test-database available at {https://github.com/pfn/keepasshttp/blob/master/test/test.kdbx}
* if on the computer designed to run the tests java isn't installed with the Unlimited Strength Java(tm) Cryptography Extension 
  an additional Key is required in the database: go to the entry "KeePassHttp Settings" and add new string field in the advanced tab 
  with name "AES Key: Test Key 128bit" and value "QVFJREJBVUdCd2dKQ2dzTQ==" (enable in-memory protection). 
* Run JUnit-test KeePassHttpConnectorTest

