package org.sonar.template.java.checks;
 
import com.google.common.collect.ImmutableList;

import org.sonar.check.Priority;
import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.semantic.Symbol.MethodSymbol;
import org.sonar.plugins.java.api.semantic.Type;
import org.sonar.plugins.java.api.tree.MethodTree;
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
    return ImmutableList.of(Kind.METHOD);
  }
  
  @Override
  public void visitNode(Tree tree) {
    MethodTree method = (MethodTree) tree;
    if (method.parameters().size() == 1) {
      MethodSymbol symbol = method.symbol();
      Type firstParameterType = symbol.parameterTypes().get(0);
      Type returnType = symbol.returnType().type();
      if (returnType.is(firstParameterType.fullyQualifiedName())) {
        reportIssue(method.simpleName(), "Never do that!");
      }
    }
  }
 
}