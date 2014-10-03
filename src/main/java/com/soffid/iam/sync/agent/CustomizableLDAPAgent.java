package com.soffid.iam.sync.agent;

import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ejb.RemoveException;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;
import com.soffid.iam.api.Group;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.AttributeDirection;
import es.caib.seycon.ng.comu.AttributeMapping;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.LlistaCorreu;
import es.caib.seycon.ng.comu.ObjectMapping;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.RoleExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource2;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;
import es.caib.seycon.ng.sync.intf.ReconcileMgr;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.Base64;

/**
 * Agente que gestiona los usuarios y contraseñas del LDAP Hace uso de las
 * librerias jldap de Novell
 * <P>
 * 
 * @author $Author: u88683 $
 * @version $Revision: 1.5 $
 */

public class CustomizableLDAPAgent extends Agent implements ExtensibleObjectMgr, UserMgr, ReconcileMgr, RoleMgr,
	AuthoritativeIdentitySource2 {

	ValueObjectMapper vom = new ValueObjectMapper();
	
	ObjectTranslator objectTranslator = null;
	
	private static final long serialVersionUID = 1L;
	boolean debugEnabled;

	// constante de máximo número de miembros de un grupo (evitar timeout)
	private static final int MAX_GROUP_MEMBERS = 5000;

	/** Puerto de conexion LDAP * */
	int ldapPort = LDAPConnection.DEFAULT_PORT;
	/** Version del servidor LDAP */
	int ldapVersion = LDAPConnection.LDAP_V3;
	/** Usuario root de conexión LDAP */
	String loginDN;
	/** Password del usuario administrador cn=root,dc=caib,dc=es */
	Password password;
	/** HOST donde se aloja LDAP */
	String ldapHost;
	/** Base DN **/
	String baseDN;
	/** ofuscador de claves SHA */
	MessageDigest digest = null;

	String usersContext;
	String rolesContext;

	// Vamos a er la hora en la que empieza y la hora en la que acaba.
	long inicio;
	long fin;
	int usuarios = 0;

	private String passwordAttribute;

	private String hashType;

	private String passwordPrefix;

	private Collection<ExtensibleObjectMapping> objectMappings;
	// --------------------------------------------------------------

	int pagesize;
	/**
	 * Constructor
	 * 
	 * @param params
	 *            Parámetros de configuración: <li>0 = código de usuario LDAP</li>
	 *            <li>1 = contraseña de acceso LDAP</li> <li>2 = host</li> <li>3
	 *            = Nombre del attribute password</li> <li>4 = Algoritmo de hash
	 *            </li>
	 */
	public CustomizableLDAPAgent() throws RemoteException {
	}

	static LDAPPool pool = new LDAPPool();
	
	@Override
	public void init() throws InternalErrorException {
		log.info("Starting LDAPAgente agent on {}", getDispatcher().getCodi(),
				null);
		loginDN = getDispatcher().getParam0();
		password = Password.decode(getDispatcher().getParam1());
		// password = params[1];
		ldapHost = getDispatcher().getParam2();
		passwordAttribute = getDispatcher().getParam3();
		if (passwordAttribute == null)
			passwordAttribute = "userPassword";
		hashType = getDispatcher().getParam4();
		if (hashType == null)
			hashType = "SHA";
		passwordPrefix = getDispatcher().getParam5();
		if (passwordPrefix == null)
			hashType = "{" + hashType + "}";
		
		baseDN = getDispatcher().getParam7();
		
		debugEnabled = "true".equals(getDispatcher().getParam8());

		try {
			if (getDispatcher().getParam6() == null || 
					getDispatcher().getParam6().trim().length() == 0)
				pagesize = 100;
			else
				pagesize = Integer.parseInt(getDispatcher().getParam6());
		} catch (NumberFormatException e) {
			throw new InternalErrorException ("Wrong numeric value "+getDispatcher().getParam6());
		}
		try {
			if (hashType != null && hashType.length() > 0)
				digest = MessageDigest.getInstance(hashType);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new InternalErrorException(
					"Unable to use SHA encryption algorithm ", e);
		}

		pool.setBaseDN(baseDN);
		pool.setLdapHost(ldapHost);
		pool.setLdapPort(ldapPort);
		pool.setLdapVersion(ldapVersion);
		pool.setLoginDN(loginDN);
		pool.setPassword(password);
		pool.setSsl(false);
	}


	/**
	 * Actualiza la contraseña del usuario. Genera la ofuscación SHA-1 y la
	 * asigna al atributo userpassword de la clase inetOrgPerson
	 * @param accountName 
	 * @throws Exception 
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void updatePassword(String accountName, ExtensibleObjects objects, Password password,
			boolean mustchange) throws Exception {

		LDAPAttribute atributo;
		LDAPEntry ldapUser;

		for (ExtensibleObject object : objects.getObjects()) {
			String dn = vom.toString(object.getAttribute("dn"));
			if (dn != null) {

				boolean repeat = false;
				do {
					try {
						ldapUser = buscarUsuario(dn); // ui puede ser nulo

						if (ldapUser == null) {
							// Generem un error perquè potser que l'usuari
							// encara
							// no esté donat d'alta al ldap [usuaris alumnes]:
							// u88683 27/01/2011
							updateObjects(accountName, objects);
							ldapUser = buscarUsuario(dn);
						}

						ArrayList modList = new ArrayList();
						if (ldapUser != null) {
							String hash = getHashPassword(password);
							atributo = new LDAPAttribute(passwordAttribute, hash);
							modList.add(new LDAPModification(
									LDAPModification.REPLACE, atributo));
							LDAPModification[] mods = new LDAPModification[modList
									.size()];
							mods = new LDAPModification[modList.size()];
							mods = (LDAPModification[]) modList.toArray(mods);
							debugModifications("Modifying password ", dn, mods);
							try {
								pool.getConnection().modify(dn, mods);
							} finally {
								pool.returnConnection();
							}
							log.info(
									"UpdateUserPassword - setting password for user {}",
									dn, null);
						}
						return;
					} catch (LDAPException e) {
						if (e.getResultCode() == LDAPException.UNWILLING_TO_PERFORM
								&& !repeat) {
							updateObjects(accountName, objects);
							repeat = true;
						} else {
							String msg = "UpdateUserPassword('" + dn + "')";
							log.warn(msg, e);
							throw new InternalErrorException(msg
									+ e.getMessage(), e);
						}
					} catch (InternalErrorException e) {
						String msg = "Error UpdateUserPassword('" + dn
								+ "'). [" + e.getMessage() + "]";
						log.warn(msg, e);
						throw e;
					}
				} while (repeat);
			}
		}
	}


	/**
	 * Busca los datos de un usuario en el directorio LDAP
	 * 
	 * @param user
	 *            codigo del usuario
	 * @return LDAPEntry entrada del directorio LDAP
	 * @throws Exception 
	 */
	private LDAPEntry buscarUsuario(String dn) throws Exception {
		try {
			return pool.getConnection().read(dn);
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
				return null;
			String msg = "buscarUsuario ('" + dn
					+ "'). Error al buscar el usuario. [" + e.getMessage()
					+ "]";
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		} finally {
			pool.returnConnection();
		}
	}

	/**
	 * Funció per obtindre transformar el password a hash per guardar a la bbdd
	 * 
	 * @param password
	 * @return
	 */
	private String getHashPassword(Password password) {
		String hash = null;
		if (digest == null)
			hash = password.getPassword();
		else
		{
			synchronized (digest) {
				hash = passwordPrefix
						+ Base64.encodeBytes(
								digest.digest(password.getPassword().getBytes()),
								Base64.DONT_BREAK_LINES);
			}
		}
		return hash;
	}

	private String[] toStringArray (Object obj)
	{
		if (obj == null)
			return null;
		else if (obj instanceof String[])
		{
			return (String[]) obj;
		}
		else if (obj instanceof Object[]) 
		{
			return vom.toStringArray((Object[])obj);
		}
		else if ("".equals(obj))
			return null;
		else
		{
			return new String[] { vom.toString(obj) };
		}
	}
	/**
	 * Añade los datos de un usuario al directorio LDAP
	 * @param accountName 
	 * 
	 * @param usuario
	 *            Informacion del usuario
	 * @throws Exception 
	 */
	public void updateObjects(String accountName, ExtensibleObjects objects)
			throws Exception {

		LDAPConnection conn = pool.getConnection();
		try {
			for (ExtensibleObject obj : objects.getObjects()) {
				String dn = vom.toString(obj.getAttribute("dn"));
				try {
					if (dn != null) {
						log.info("Updating object {}", dn, null);
						LDAPEntry entry = buscarUsuario(dn);
						if (entry == null) {
							if (debugEnabled)
							{
								log.info("================================================");
								log.info("Creating object "+dn);
							}
							LDAPAttributeSet attributeSet = new LDAPAttributeSet();
							for (String attribute : obj.getAttributes()) {
								String values[] = toStringArray(obj.getAttribute(attribute));
								if (values != null && !"dn".equals(attribute))
								{
									LDAPAttribute att = new LDAPAttribute(attribute,values);
									attributeSet.add(att);
									if (debugEnabled)
										debugAttribute(LDAPModification.ADD, att);
								}
							}
							if (debugEnabled)
								log.info("================================================");
							entry = new LDAPEntry(dn, attributeSet);
							conn.add(entry);
							if (accountName != null) {
								Password p = getServer().getAccountPassword(
										accountName, getCodi());
								if (p != null) {
									updatePassword(accountName, objects, p, false);
								} else {
									p = getServer().generateFakePassword(
											accountName, getCodi());
									updatePassword(accountName, objects, p, true);
								}
	
							}
						} else {
							LinkedList<LDAPModification> modList = new LinkedList<LDAPModification>();
							for (String attribute : obj.getAttributes()) {
								if (!"dn".equals(attribute) &&  !"objectClass".equals(attribute))
								{
									Object v = obj.getAttribute (attribute);
									String[] value = toStringArray(obj.getAttribute(attribute));
									if (value != null && value.length == 1 && value[0].trim().length() == 0)
										value = null;
									if (value == null
											&& entry.getAttribute(attribute) != null) {
										modList.add(new LDAPModification(
												LDAPModification.DELETE,
												new LDAPAttribute(attribute)));
									} else if (value != null
											&& entry.getAttribute(attribute) == null) {
										modList.add(new LDAPModification(
												LDAPModification.ADD,
												new LDAPAttribute(attribute, value)));
									} else if (value != null
											&& entry.getAttribute(attribute) != null) {
										if (v instanceof byte[])
											modList.add(new LDAPModification(
													LDAPModification.REPLACE,
													new LDAPAttribute(attribute, (byte[])v)));
										else
										{
											boolean update = false;
											String []oldvalue = entry.getAttribute(attribute).getStringValueArray();
											if (value.length != oldvalue.length)
												update = true;
											else
											{
												for (int i = 0;i < value.length; i++)
												{
													if (!value[i].equals(oldvalue[i]))
													{
														update = true;
														break;
													}
												}
												if (update)
													modList.add(new LDAPModification(
															LDAPModification.REPLACE,
															new LDAPAttribute(attribute, value)));
											}
											
										}
									}
								}
							}
							LDAPModification[] mods = new LDAPModification[modList
									.size()];
							mods = new LDAPModification[modList.size()];
							mods = (LDAPModification[]) modList.toArray(mods);
							debugModifications("Modifying", dn, mods);
							conn.modify(dn, mods);
						}
					}
				} catch (Exception e) {
					String msg = "updating object : " + dn;
					log.warn(msg, e);
					throw new InternalErrorException(msg, e);
				}
			}
		} finally {
			pool.returnConnection();
		}
	}

	public void removeObjects(ExtensibleObjects objects)
			throws Exception {
		LDAPConnection conn = pool.getConnection();
		try 
		{
			for (ExtensibleObject object : objects.getObjects()) {
				String dn = vom.toString(object.getAttribute("dn"));
				try {
					if (dn != null) {
						log.info("Updating object {}", dn, null);
						conn.delete(dn);
					}
				} catch (Exception e) {
					String msg = "updating object : " + dn;
					log.warn(msg, e);
					throw new InternalErrorException(msg, e);
				}
			}
		} finally {
			pool.returnConnection();
		}
	}

	public boolean validatePassword(ExtensibleObjects objects, Password password)
			throws RemoteException, InternalErrorException {
		try {
			LDAPConnection conn = new LDAPConnection();
			conn.connect(ldapHost, ldapPort);
			conn.bind(ldapVersion, loginDN, password.getPassword().getBytes("UTF8"));
			conn.disconnect();
			return true;
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.INSUFFICIENT_ACCESS_RIGHTS || 
					e.getResultCode() == LDAPException.INVALID_CREDENTIALS)
				return false;
			else
				throw new InternalErrorException ("Error connecting to LDAP", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error connecting to LDAP", e);
		}
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects) throws RemoteException,
			InternalErrorException {
		this.objectMappings  = objects;
		objectTranslator = new ObjectTranslator(getDispatcher(), getServer(), objectMappings);
		
	}

	public Collection<ExtensibleObject> findObjects(ExtensibleObject objectQuery)
			throws Exception {
		LDAPConnection conn = pool.getConnection();
		try
		{
			StringBuffer buf = new StringBuffer ();
			buildQuery(objectQuery, buf);
			try {
				Collection<ExtensibleObject> objs = new LinkedList<ExtensibleObject>(); 
				LDAPSearchResults query = conn.search(baseDN, LDAPConnection.SCOPE_SUB, buf.toString(), null, false);
				while (query.hasMore())
				{
					try {
						LDAPEntry entry = query.next();
						ExtensibleObject obj = new ExtensibleObject();
						obj.setAttribute("dn", entry.getDN());
						for (Object attrName: entry.getAttributeSet())
						{
							LDAPAttribute attribute = entry.getAttribute((String) attrName);
							if (attribute.getStringValueArray().length == 0)
								obj.setAttribute((String) attrName, attribute.getStringValue());
							else
								obj.setAttribute((String) attrName, attribute.getStringValueArray());
						}
						objs.add(obj);
					} catch (LDAPException e) 
					{
						if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
							break;
						else
							throw e;
					}
				}
				return objs;
			} catch (LDAPException e) {
				String msg = "error search objects : " + baseDN+": "+buf.toString();
				log.warn(msg, e);
				throw new InternalErrorException(msg, e);
			}
		} finally {
			pool.returnConnection();
		}
		
	}

	private boolean buildQuery(ExtensibleObject objectQuery, StringBuffer buf) {
		boolean any = false;
		for (String attribute : objectQuery.getAttributes()) {
			if (! attribute.equals("dn"))
			{
				String [] values = toStringArray(objectQuery.getAttribute(attribute));
				if (values != null && values.length > 0)
				{
					any = true;
					if (buf.length() == 0)
						buf.append ("(&");
					if (values.length > 1)
						buf.append ("(|");
					for (String value: values)
					{
						buf.append ("(")
							.append (attribute)
							.append ("=")
							.append (value)
							.append(")");
					}
					if (values.length > 1)
						buf.append (")");
				}
			}
		}
		
		if (buf.length() > 0)
			buf.append (")");
		
		if (debugEnabled)
			log.info("Performing query "+buf.toString());
		return any;
	}

	AttributeMapping findAttribute (ExtensibleObjectMapping objectMapping, String attribute)
	{
		for (AttributeMapping attMapping: objectMapping.getAttributes())
		{
			if (attMapping.getSystemAttribute().equals(attribute) && (
					attMapping.getDirection().equals (AttributeDirection.OUTPUT) || 
					attMapping.getDirection().equals(AttributeDirection.INPUTOUTPUT)))
			{
				return attMapping;
			}
		}
		return null;
	}
	
	LinkedList<String> getSoffidAccounts (SoffidObjectType type) throws Exception
	{
		LDAPConnection conn;
		conn = pool.getConnection();
		try
		{
			LinkedList<String> accounts = new LinkedList<String>();
			
			ExtensibleObject dummySoffidObj = new ExtensibleObject();
			dummySoffidObj.setObjectType (type.getValue());
			
			for (ExtensibleObjectMapping mapping: objectMappings )
			{
				if (mapping.getSoffidObject().equals(type))
				{
					ExtensibleObject dummySystemObject = objectTranslator.generateObject(dummySoffidObj, mapping, true);
					
					StringBuffer sb = new StringBuffer();
					boolean any = buildQuery(dummySystemObject, sb);
					
					if (any)
					{
						LDAPSearchConstraints oldConst = conn.getSearchConstraints();	// Save search constraints
						LDAPPagedResultsControl pageResult = null;
						if (pagesize > 0)
							pageResult =
								new LDAPPagedResultsControl(pagesize,  false);
	
						do
						{
							LDAPSearchConstraints constraints = conn.getSearchConstraints();
							if (pageResult != null)
								constraints.setControls(pageResult);
							constraints.setMaxResults(0);
							conn.setConstraints(constraints);
	
							LDAPSearchResults searchResults = conn.search(baseDN, LDAPConnection.SCOPE_SUB, sb.toString(), null, false);
	
							// Process results
							while (searchResults.hasMore())
							{
								try {
									System.out.println ("Accounts : "+accounts.size()+ " ");
									LDAPEntry entry = searchResults.next();
									ExtensibleObject eo = parseEntry (entry, mapping);
									ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
									for (ExtensibleObject eo2: parsed.getObjects())
									{
										Account account = vom.parseAccount(eo2);
										if (account != null)
											accounts.add(account.getName());
									}
								} catch (LDAPException e) {
									if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
										break;
									else
										throw e;
								}
							}
	
							if (pageResult != null)
							{
								LDAPControl responseControls[] = searchResults.getResponseControls();
								pageResult.setCookie(null); // in case no cookie is returned we need
																						// to step out of do..while
		
								if (responseControls != null)
								{
									for (int i = 0; i < responseControls.length; i++)
									{
										if (responseControls[i] instanceof LDAPPagedResultsResponse)
										{
											LDAPPagedResultsResponse response =
													(LDAPPagedResultsResponse) responseControls[i];
											pageResult.setCookie(response.getCookie());
										}
									}
								}
							}
						} while (pageResult != null && pageResult.getCookie() != null);
						conn.setConstraints(oldConst);
					}
				}
			}
			return accounts;
		} finally {
			pool.returnConnection();
		}

	}

	
	LinkedList<ExtensibleObject> getLdapObjects (SoffidObjectType type, String first, int count) throws LDAPException, InternalErrorException
	{
		
		LDAPConnection conn;
		try {
			conn = pool.getConnection();
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to LDAP Server", e1);
		}
		try
		{
			ExtensibleObject dummySoffidObj = new ExtensibleObject();
			LinkedList<ExtensibleObject> objects = new LinkedList<ExtensibleObject>();
			dummySoffidObj.setObjectType (type.getValue());
			
			boolean start = first == null;
			
			for (ExtensibleObjectMapping mapping: objectMappings )
			{
				if (mapping.getSoffidObject().equals(type))
				{
					ExtensibleObject dummySystemObject = objectTranslator.generateObject(dummySoffidObj, mapping, true);
					
					StringBuffer sb = new StringBuffer();
					boolean any = buildQuery(dummySystemObject, sb);
					
					if (any)
					{
						LDAPConnection lc = conn;
						LDAPSearchConstraints oldConst = lc.getSearchConstraints();	// Save search constraints
						LDAPPagedResultsControl pageResult = null;
						if (count > 0)
							pageResult =
								new LDAPPagedResultsControl(count,  false);
				
	
						do
						{
							LDAPSearchConstraints constraints = lc.getSearchConstraints();
							if (pageResult != null) constraints.setControls(pageResult);
							constraints.setMaxResults(0);
							lc.setConstraints(constraints);
	
							
							log.debug("Searching for "+sb.toString()+" on "+baseDN);
							
							LDAPSearchResults searchResults = lc.search(baseDN, LDAPConnection.SCOPE_SUB, sb.toString(), null, false);
	
							// Process results
							while (searchResults.hasMore())
							{
								try {
									LDAPEntry entry = searchResults.next();
									if (!start)
									{
										if (entry.getDN().equals(first))
											start = true;
									}
									else
									{
										ExtensibleObject eo = parseEntry (entry, mapping);
										objects.add(eo);
										if (count -- == 0)
											break;
									}
								} 
								catch (LDAPException e) 
								{
									if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
										break;
									else
										throw e;
								}
							}
	
							if (pageResult != null)
							{
								LDAPControl responseControls[] = searchResults.getResponseControls();
								pageResult.setCookie(null); // in case no cookie is returned we need
								if (responseControls != null)
								{
									for (int i = 0; i < responseControls.length; i++)
									{
										if (responseControls[i] instanceof LDAPPagedResultsResponse)
										{
											LDAPPagedResultsResponse response =
													(LDAPPagedResultsResponse) responseControls[i];
											pageResult.setCookie(response.getCookie());
										}
									}
								}
							}
						} while (pageResult != null && pageResult.getCookie() != null && count > 0);
						lc.getSearchConstraints().setControls(new LDAPControl[0]);
					}
				}
			}
			return objects;
		} finally {
			pool.returnConnection();
		}
	}

	
	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		
		Set<String>accounts = new HashSet<String>();
		try {
			accounts.addAll(getSoffidAccounts(SoffidObjectType.OBJECT_USER));
			accounts.addAll(getSoffidAccounts(SoffidObjectType.OBJECT_ACCOUNT));
		} catch (Exception e) {
			throw new InternalErrorException ("Error getting accounts list", e);
		}
		return new LinkedList<String>(accounts);
	}

	public ExtensibleObject parseEntry (LDAPEntry entry, ObjectMapping mapping)
	{
		ExtensibleObject eo = new ExtensibleObject();
		eo.setAttribute("dn", entry.getDN());
		eo.setObjectType(mapping.getSystemObject());
		for (Object obj: entry.getAttributeSet())
		{
			LDAPAttribute att = (LDAPAttribute) obj;
			if (att.getStringValueArray().length == 1)
				eo.setAttribute(att.getName(), att.getStringValue());
			else
				eo.setAttribute(att.getName(), att.getStringValueArray());
		}
		return eo;
	}
	
	
	public Usuari getUserInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		try {
			ExtensibleObject eo = findExtensibleUser (userAccount);
			if (eo == null)
				return null;
			ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
			for (ExtensibleObject peo: parsed.getObjects())
			{
				Usuari usuari = vom.parseUsuari(peo);
				if (usuari != null)
					return usuari;
				Account account = vom.parseAccount(peo);
				if (account != null)
				{
					usuari = new Usuari();
					usuari.setCodi(account.getName());
					usuari.setFullName(account.getDescription());
					usuari.setPrimerLlinatge(account.getDescription());
					usuari.setNom("-");
					return usuari;
				}
			}
			return null;
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}

	}
	
	private ExtensibleObject findExtensibleUser (String userAccount) throws Exception
	{
		// Generate a dummy object to perform query
		ExtensibleObject account = new ExtensibleObject();
		account.setObjectType(SoffidObjectType.OBJECT_ACCOUNT.getValue());
		account.setAttribute("accountName", userAccount);
		ExtensibleObject found = findUserByExample(account);
		if (found != null)
			return found;
		// 
		ExtensibleObject user = new ExtensibleObject();
		user.setObjectType(SoffidObjectType.OBJECT_USER.getValue());
		user.setAttribute("accountName", userAccount);
		return findUserByExample(user);
	}
	
	private ExtensibleObject findUserByExample (ExtensibleObject example) throws Exception
	{
		// For each suitable mappping
		for (ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().toString().equals(example.getObjectType()))
			{
				// Generate system objects from source user
				ExtensibleObject systemObject = objectTranslator.generateObject(example, objectMapping, true);
				
				String dn = vom.toString(systemObject.getAttribute("dn"));
				if (dn != null)
				{
					// Search object by dn
					LDAPEntry entry = buscarUsuario(dn);
					if (entry != null)
					{
						return parseEntry (entry, objectMapping);
					}
				}
			}
		}
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		Set<String>roles = new HashSet<String>();
		try {
			for (ExtensibleObject eo: getLdapObjects(SoffidObjectType.OBJECT_ROLE, null, 0))
			{
				ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
				for (ExtensibleObject parsedObject : parsed.getObjects())
				{
					Rol rol = vom.parseRol(parsedObject);
					if (rol != null)
						roles.add (rol.getNom());
				}
				
			}
		} catch (LDAPException e) {
			throw new InternalErrorException ("Error getting accounts list", e);
		}
		return new LinkedList<String>(roles);
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		try {
			ExtensibleObject rolObject = new ExtensibleObject();
			rolObject.setObjectType(SoffidObjectType.OBJECT_ROLE.getValue());
			rolObject.setAttribute("name", roleName);
			rolObject.setAttribute("system", getDispatcher().getCodi());
			
			// Generate a dummy object to perform query
			ExtensibleObjects systemObjects = objectTranslator.generateObjects(rolObject);
			for (ExtensibleObject systemObject: systemObjects.getObjects())
			{
				String dn = vom.toString(systemObject.getAttribute("dn"));
				if (dn != null)
				{
					LDAPEntry entry = buscarUsuario(dn);
					if (entry != null)
					{
						for (ExtensibleObjectMapping objectMapping: objectMappings)
						{
							if (objectMapping.getSoffidObject().equals(rolObject.getObjectType()))
							{
								ExtensibleObject eo = parseEntry (entry, objectMapping);
								ExtensibleObject parsed = objectTranslator.parseInputObject(eo, objectMapping);
								if (parsed != null)
								{
									Rol rol = vom.parseRol(parsed);
									if (rol != null)
										return rol;
								}
							}
						}
					}
				}
			}
			return null;
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public List<Rol> getAccountRoles(String userAccount)
			throws RemoteException, InternalErrorException {
		List<Rol> roles;
		try {
			roles = new LinkedList();
			if (!populateRolesFromUser(userAccount, roles))
				populateRolesFromRol(userAccount, roles);
		} catch (Exception e) {
			throw new InternalErrorException("Error accessing LDAP", e);
		}
		return roles;
	}

	private boolean populateRolesFromUser(String userAccount, List<Rol> roles) throws Exception 
	{
		boolean found = false;
		ExtensibleObject userObject = findExtensibleUser(userAccount);
		if (userObject != null)
		{
			ExtensibleObjects soffidObjects = objectTranslator.parseInputObjects(userObject);
			for (ExtensibleObject soffidObject:soffidObjects.getObjects())
			{
				List<Map<String,Object>>grantedRoles = (List<Map<String, Object>>) soffidObject.get("grantedRoles");
				if (grantedRoles != null)
				{
					for (Map<String,Object> grantedRole: grantedRoles)
					{
						Rol rol = new Rol ();
						rol.setBaseDeDades(getDispatcher().getCodi());
						rol.setNom(vom.toSingleString(grantedRole.get("grantedRole")));
						rol.setDescripcio(rol.getNom()+" Auto generated");
						roles.add (rol);
					}
					found = true;
				}
				List<String> granted = (List<String>) soffidObject.get("granted");
				if (granted != null)
				{
					for (String grantedRole: granted)
					{
						Rol rol = new Rol ();
						rol.setBaseDeDades(getDispatcher().getCodi());
						rol.setNom(grantedRole);
						rol.setDescripcio(rol.getNom()+" Auto generated");
						roles.add (rol);
					}
					found = true;
				}
				
			}
		}
		
		return found;
	}

	private boolean populateRolesFromRol(String userAccount, List<Rol> roles) throws Exception 
	{
		LDAPConnection conn = pool.getConnection();
		try 
		{
			boolean found = false;
			ExtensibleObject rolObject = new ExtensibleObject();
			rolObject.setObjectType(SoffidObjectType.OBJECT_ROLE.getValue());
			///
			Map<String,Object> userMap = new HashMap<String, Object>();
			userMap.put ("accountName", userAccount);
			userMap.put ("system", getDispatcher().getCodi());
			List<Map<String,Object> > userMapList = new LinkedList<Map<String,Object>>();
			userMapList.add(userMap);
			rolObject.setAttribute("allGrantedAccounts",  userMap);
			rolObject.setAttribute("grantedAccounts",  userMap);
			List<String> accountNames = new LinkedList<String>();
			accountNames.add(userAccount);
			rolObject.setAttribute("allGrantedAccountNames", accountNames);
			rolObject.setAttribute("grantedAccountNames", accountNames);
			
			// Generate a dummy object to perform query
			ExtensibleObjects systemObjects = objectTranslator.generateObjects(rolObject);
			for (ExtensibleObject systemObject: systemObjects.getObjects())
			{
				StringBuffer sb = new StringBuffer();
				
				sb.append ("(&");
				boolean any = buildQuery(systemObject, sb);
				if (any && baseDN != null)
				{
					LDAPSearchResults search = conn.search(baseDN, LDAPConnection.SCOPE_SUB, sb.toString(), null, false);
					while (search.hasMore())
					{
						try {
							LDAPEntry roleEntry = search.next();
							for (ExtensibleObjectMapping objectMapping: objectMappings)
							{
								if (objectMapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ROLE))
								{
									ExtensibleObject roleObject = parseEntry(roleEntry, objectMapping);
									ExtensibleObject soffidObject = objectTranslator.parseInputObject(roleObject, objectMapping);
									Rol rol = vom.parseRol(soffidObject);
									if (rol != null)
									{
										roles.add(rol);
									}
								}
							}
							found = true;
						} catch (LDAPException e) 
						{
							if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
								break;
							else
								throw e;
						}
						
					}
				}
			}
	
			return found;
		} finally {
			pool.returnConnection();
		}
	}

	public void updateUser(String userName, Usuari userData)
			throws RemoteException, InternalErrorException {
		Account account = new Account();
		account.setName(userName);
		account.setDescription(userData.getFullName());
		account.setDisabled(false);
		account.setDispatcher(getDispatcher().getCodi());
		ExtensibleObjects objects = objectTranslator.generateObjects(new UserExtensibleObject(account, userData, getServer()));
		try
		{
			updateObjects(userName, objects);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		Account account = new Account();
		account.setName(accountName);
		account.setDescription(description);
		account.setDisabled(false);
		account.setDispatcher(getDispatcher().getCodi());
		ExtensibleObjects objects = objectTranslator.generateObjects(new AccountExtensibleObject(account, getServer()));
		try
		{
			updateObjects(accountName, objects);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public void removeUser(String userName) throws RemoteException,
			InternalErrorException {
		Account account = new Account();
		account.setName(userName);
		account.setDescription(userName);
		account.setDisabled(false);
		account.setDispatcher(getDispatcher().getCodi());
		ExtensibleObjects objects;

		try {
			Usuari user = getServer().getUserInfo(userName, getDispatcher().getCodi());
			objects = objectTranslator.generateObjects(new UserExtensibleObject(account, user, getServer()));
		} catch (UnknownUserException e) {
			objects = objectTranslator.generateObjects(new AccountExtensibleObject(account, getServer()));
		}
		try
		{
			removeObjects(objects);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public void updateUserPassword(String userName, Usuari userData,
			Password password, boolean mustchange) throws RemoteException,
			InternalErrorException {
		Account account = new Account();
		account.setName(userName);
		account.setDescription(userData.getFullName());
		account.setDisabled(false);
		account.setDispatcher(getDispatcher().getCodi());
		ExtensibleObjects objects = objectTranslator.generateObjects(new UserExtensibleObject(account, userData, getServer()));
		try
		{
			updatePassword(userName, objects, password, mustchange);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public boolean validateUserPassword (String user, Password password)
			throws RemoteException, InternalErrorException
	{
		LDAPConnection conn = null;
		try
		{
			Account acc = new Account();
			acc.setName(user);
			acc.setDescription(user);
			acc.setDispatcher(getDispatcher().getCodi());
			ExtensibleObjects entries;
			try
			{
				Usuari usuari = getServer().getUserInfo(user, getDispatcher().getCodi());
				entries = objectTranslator.generateObjects(new UserExtensibleObject(acc, usuari, getServer()));
			} catch (UnknownUserException e)
			{
				entries = objectTranslator.generateObjects(new AccountExtensibleObject(acc, getServer()));
			}
			for (ExtensibleObject entry: entries.getObjects())
			{
				try
				{
					String dn = vom.toSingleString(entry.getAttribute("dn"));
					if (dn != null)
					{
						conn = new LDAPConnection(new LDAPJSSESecureSocketFactory());
						conn.connect(ldapHost, ldapPort);
						conn.bind(ldapVersion, dn, password.getPassword().getBytes("UTF8"));
						conn.disconnect();
						return true;
					}
				}
				catch (LDAPException e)
				{
						log.info("Error connecting as user " + user + ":" + e.toString());
				}
			}
			return false;
		}
		catch (UnsupportedEncodingException e)
		{
			return false;
		}
		finally {}
	}
	
	

	public void updateRole(Rol rol) throws RemoteException,
			InternalErrorException {
		ExtensibleObjects objects = objectTranslator.generateObjects(new RoleExtensibleObject(rol, getServer()));
		
		try {
			updateObjects(null, objects);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public void removeRole(String rolName, String dispatcher)
			throws RemoteException, InternalErrorException {
		Rol rol = new Rol();
		rol.setNom(rolName);
		rol.setBaseDeDades(dispatcher);
		ExtensibleObjects objects = objectTranslator.generateObjects(new RoleExtensibleObject(rol, getServer()));
		try {
			removeObjects(objects);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	private String firstChange = null;
	public Collection<AuthoritativeChange> getChanges(String nextChange)
			throws InternalErrorException {
		Collection<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		try {
			LinkedList<ExtensibleObject> objects = getLdapObjects(SoffidObjectType.OBJECT_USER, firstChange, pagesize);
			if (objects.isEmpty())
			{
				firstChange = null;
			}
			
			for (ExtensibleObject ldapObject: objects)
			{
				debugObject("LDAP Object", ldapObject, "");
				firstChange = vom.toSingleString(ldapObject.getAttribute("dn"));
				ExtensibleObjects parsedObjects = objectTranslator.parseInputObjects(ldapObject);
				for (ExtensibleObject object: parsedObjects.getObjects())
				{
					debugObject("Parsed Object", object, "");
					Usuari user = vom.parseUsuari(object);
					if (user != null)
					{
						if (debugEnabled)
							log.info("Resulting object. "+user.toString());
						AuthoritativeChange change = new AuthoritativeChange();
						
						AuthoritativeChangeIdentifier id = new AuthoritativeChangeIdentifier();
						change.setId(id);
						id.setChangeId(null);
						id.setEmployeeId(user.getCodi());
						id.setDate(new Date());
						
						change.setUser( user );
						
						Object groups = object.getAttribute("secondaryGroups");
						if (groups instanceof Collection)
						{
							Set<String> groupsList = new HashSet<String>();
							for (Object group: (Collection<Object>) object)
							{
								if (group instanceof String)
								{
									groupsList.add ((String) group);
								}
								else if (group instanceof ExtensibleObject)
								{
									Object name = (String) ((ExtensibleObject) group).getAttribute("name");
									if (name != null)
										groupsList.add (name.toString());
								}
								else if (group instanceof Group)
								{
									groupsList.add (((Group) group).getName());
								}
								else if (group instanceof Grup)
								{
									groupsList.add(((Grup) group).getCodi());
								}
							}
							change.setGroups(groupsList);
						}
						
						Object attributes = object.getAttribute("attributes");
						if (attributes instanceof Map)
						{
							Map<String,Object> attributesMap = new HashMap<String, Object>();
							for (Object attributeName: ((Map)attributes).keySet())
							{
								attributesMap.put((String)attributeName, (String) vom.toSingleString(((Map)attributes).get(attributeName)));
							}
							change.setAttributes(attributesMap);
						}
						
						changes.add(change);
						
					}
				}
				
			}
		} catch (LDAPException e) {
			throw new InternalErrorException ("Error getting accounts list", e);
		}
		return changes;
	}

	public void debugModifications (String action, String dn, LDAPModification mods[])
	{
		if (debugEnabled)
		{
			log.info ("=========================================================");
			log.info(action + " object "+dn);
			for (int i = 0; i < mods.length; i++)
			{
				LDAPModification mod = mods[i];
				debugAttribute(mod.getOp(), mod.getAttribute());
			}
			log.info ("=========================================================");
		}
	}

	private void debugAttribute(int op, LDAPAttribute ldapAttribute) {
		String attAction = op == LDAPModification.ADD ? "ADD" :
			op == LDAPModification.DELETE? "DELETE": "REPLACE";
		StringBuffer b = new StringBuffer(attAction);
		b.append (" ")
			.append (ldapAttribute.getName());
		if (op != LDAPModification.DELETE)
		{
			b.append (" = [");
			String[] v = ldapAttribute.getStringValueArray();
			for (int j = 0; j < v.length; j++)
			{
				if (j > 0) b.append (", ");
				b.append (v[j]);
			}
			b.append ("]");
		}
		log.info(b.toString());
	}

	public boolean hasMoreData() throws InternalErrorException {
		return firstChange != null;
	}

	public String getNextChange() throws InternalErrorException {
		return null;
	}

	void debugObject (String msg, Map<String,Object> obj, String indent)
	{
		if (debugEnabled)
		{
			if (msg != null)
				log.info(indent + msg);
			for (String attribute: obj.keySet())
			{
				Object subObj = obj.get(attribute);
				if (subObj == null)
				{
					log.info (indent+attribute.toString()+": null");
				}
				else if (subObj instanceof Map)
				{
					log.info (indent+attribute.toString()+": Object {");
					debugObject (null, (Map<String, Object>) subObj, indent + "   ");
					log.info (indent+"}");
				}
				else
				{
					log.info (indent+attribute.toString()+": "+subObj.toString());
				}
			}
		}
	}
}
	