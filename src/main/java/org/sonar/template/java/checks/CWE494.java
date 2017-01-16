package org.sonar.template.java.checks;
 
import com.google.common.collect.ImmutableList;

import org.sonar.check.Priority;
import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.Tree.Kind;
 
import java.util.List;
 
@Rule(
  key = "CWE-494",
  name = "Download of Code Without Integrity Check",
  description = "",
  priority = Priority.MAJOR,
  tags = {"sans-top25-risky"})

public class CWE494 extends IssuableSubscriptionVisitor {
 
  @Override
  public List<Kind> nodesToVisit() {
    return ImmutableList.of(Kind.METHOD_INVOCATION);
  }
  
  @Override
  public void visitNode(Tree tree) {
	  MethodInvocationTree lt = (MethodInvocationTree) tree;
	  if(lt.symbol().name().equals("update")){
		  reportIssue(lt, "Never do that!");
	  }

  }
 
}