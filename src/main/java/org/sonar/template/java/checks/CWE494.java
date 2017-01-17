package org.sonar.template.java.checks;

import com.google.common.collect.ImmutableList;

import org.sonar.check.Priority;
import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.ClassTree;
import org.sonar.plugins.java.api.tree.MemberSelectExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.Tree.Kind;
import org.sonar.plugins.java.api.tree.VariableTree;

import java.util.ArrayList;
import java.util.List;

@Rule(key = "CWE-494", name = "Download of Code Without Integrity Check", description = "", priority = Priority.MAJOR, tags = {
		"sans-top25-risky" })

public class CWE494 extends IssuableSubscriptionVisitor {

	private ArrayList<String> MessageDigestVariables;

	public CWE494() {
		MessageDigestVariables = new ArrayList<>();
	}

	@Override
	public List<Kind> nodesToVisit() {
		return ImmutableList.of(Kind.VARIABLE, Kind.METHOD_INVOCATION);
	}

	@Override
	public void visitNode(Tree tree) {
		if (tree instanceof VariableTree) {
			VariableTree vt = (VariableTree) tree;
			if (vt.type().toString().equals("MessageDigest")) {
				MessageDigestVariables.add(vt.simpleName().toString());
			}
		} else if (tree instanceof MethodInvocationTree) {
			MethodInvocationTree mit = (MethodInvocationTree) tree;
			if (mit.methodSelect().is(Kind.MEMBER_SELECT)) {
				MemberSelectExpressionTree ms = (MemberSelectExpressionTree) mit.methodSelect();
				if (MessageDigestVariables.contains(ms.firstToken().text())) {
					if (ms.identifier().name().equals("update")) {
						if (!mit.arguments().get(0).kind().toString().equals("PLUS")) {
							reportIssue(mit, "You need to add salt");
						}
					}
				}
			}
		}

	}

}