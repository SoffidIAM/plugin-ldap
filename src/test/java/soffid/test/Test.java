package soffid.test;

import com.novell.ldap.LDAPAttributeSchema;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSchema;

public class Test {
	public static void main( String args[]) throws LDAPException {
		LDAPConnection conn = new LDAPConnection();
		conn.connect("localhost", 389);
		conn.bind("cn=admin,dc=nodomain", "changeit");
		
		String c = conn.getSchemaDN();
		System.out.println(c);
		
		LDAPSchema entry = conn.fetchSchema(c);
		
		LDAPAttributeSchema p = entry.getAttributeSchema("jpegPhoto");
		System.out.println(p);
		for (String s: p.getStringValueArray())
			System.out.println(s);
		System.out.println("-------");
		for (String s: p.getNames())
			System.out.println(s);
		System.out.println(p.getSyntaxString());
	}
}
