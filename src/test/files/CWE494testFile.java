class MyClass {
	
  MyClass(MyClass mc) { }
 
  void loginWithoutSalt1(String user, String pass){
	  MessageDigest encer = MessageDigest.getInstance("SHA"); 
	  encer.update(pass);  // Noncompliant
	  byte[] digest = encer.digest();
	  if (equal(digest,secret_password(user))) {
		  login_user();
	  }
  }
  
  void loginWithSalt1(String user, String pass){
	  String salt = getSalt(user);
	  MessageDigest encer = MessageDigest.getInstance("SHA");  
	  encer.update(pass+salt);
	  byte[] digest = encer.digest();
	  if (equal(digest,secret_password(user))) {
		  login_user();
	  }
  }

}