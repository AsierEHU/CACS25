package org.sonar.template.java.checks;
import org.junit.Test;
import org.sonar.java.checks.verifier.JavaCheckVerifier;

public class MyFirstCustomCheckTestLO {

	  @Test
	  public void test() {
		  
		  JavaCheckVerifier.verify("src/test/files/MyFirstCustomCheckLO.java", new MyFirstCustomCheckLO());
	  }
	
}
