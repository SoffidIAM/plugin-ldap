package com.soffid.iam.sync.agent;

import java.io.UnsupportedEncodingException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.novell.ldap.LDAPAuthHandler;
import com.novell.ldap.LDAPAuthProvider;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.pool.AbstractPool;

public class LDAPPool extends AbstractPool<LDAPConnection> {
	Log log = LogFactory.getLog(getClass());
	String loginDN;
	Password password;
	private String ldapHost;
	private int ldapPort;
	private int ldapVersion;
	private String baseDN;
	private boolean ssl;
	
	public boolean isSsl() {
		return ssl;
	}

	public void setSsl(boolean ssl) {
		if (this.ssl  != ssl)
		{
			this.ssl = ssl;
			reconfigure();
		}
	}

	public String getLdapHost() {
		return ldapHost;
	}

	public void setLdapHost(String ldapHost) {
		if (this.ldapHost == null || ! this.ldapHost.equals(ldapHost))
		{
			this.ldapHost = ldapHost;
			reconfigure();
		}
	}

	public int getLdapPort() {
		return ldapPort;
	}

	public void setLdapPort(int ldapPort) {
		if (this.ldapPort  != ldapPort)
		{
			this.ldapPort = ldapPort;
			reconfigure();
		}
	}

	public int getLdapVersion() {
		return ldapVersion;
	}

	public void setLdapVersion(int ldapVersion) {
		if (this.ldapVersion  != ldapVersion)
		{
			this.ldapVersion = ldapVersion;
			reconfigure();
		}
	}

	public String getBaseDN() {
		return baseDN;
	}

	public void setBaseDN(String baseDN) {
		if (this.baseDN == null || ! this.baseDN.equals(baseDN))
		{
			this.baseDN = baseDN;
			reconfigure();
		}
	}

	public String getLoginDN() {
		return loginDN;
	}

	public void setLoginDN(String loginDN) {
		if (this.loginDN == null || ! this.loginDN.equals(loginDN))
		{
			this.loginDN = loginDN;
			reconfigure();
		}
	}

	public Password getPassword() {
		return password;
	}

	public void setPassword(Password password) {
		if (this.password == null || ! this.password.equals(password))
		{
			this.password = password;
			reconfigure();
		}
	}

	@Override
	protected LDAPConnection createConnection() throws Exception {
		LDAPConnection conn ;
		if (isSsl())
			conn = new LDAPConnection(new LDAPJSSESecureSocketFactory());
		else
			conn = new LDAPConnection();

		conn.setSocketTimeOut(60_000);
		try 
		{
			LDAPConstraints constraints = conn.getConstraints();
			constraints.setReferralFollowing(true);
			constraints.setReferralHandler(new LDAPAuthHandler()
			{
				public LDAPAuthProvider getAuthProvider (String host, int port)
				{
					try
					{
//						log.info("Authenticating against "+host+":"+port);
						return new LDAPAuthProvider(loginDN+ ", " + baseDN, password.getPassword()
								.getBytes("UTF-8"));
					}
					catch (UnsupportedEncodingException e)
					{
						return new LDAPAuthProvider(loginDN, password.getPassword()
								.getBytes());
					}
				}
			});
			conn.setConstraints(constraints);
//			log.info("Connecting to " + (isSsl() ? "ldaps://": "ldap://") +ldapHost+":"+ldapPort);
			conn.connect(ldapHost, ldapPort);
//			log.info("Binding as " + loginDN);
			conn.bind(ldapVersion, loginDN , password.getPassword()
					.getBytes("UTF8"));
		}
		catch (UnsupportedEncodingException e)
		{
			throw new InternalErrorException("Error encoding UTF8:" + e.toString(),
					e);
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException("Failed to connect to LDAP: ("
					+ loginDN + "/" + password.getPassword() + " host="+ldapHost+")" + e.toString(), e);
		}
		return (conn);
	}

	@Override
	protected boolean isConnectionValid(LDAPConnection connection)
			throws Exception {
		return connection.isConnectionAlive();
	}

	@Override
	protected void closeConnection(LDAPConnection connection) throws Exception {
		connection.disconnect();
	}

}
