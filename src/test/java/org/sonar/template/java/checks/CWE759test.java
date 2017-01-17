package org.sonar.template.java.checks;
import org.junit.Test;
import org.sonar.java.checks.verifier.JavaCheckVerifier;

public class CWE759test {

	  @Test
	  public void test() {
		  
		  JavaCheckVerifier.verify("src/test/files/CWE759testFile.java", new CWE759());
	  }
	
}
