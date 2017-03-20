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
import com.novell.ldap.LDAPReferralException;
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
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource;
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
	AuthoritativeIdentitySource {

	ValueObjectMapper vom = new ValueObjectMapper();
	
	ObjectTranslator objectTranslator = null;
	
	private static final long serialVersionUID = 1L;

	// constante de máximo número de miembros de un grupo (evitar timeout)
	private static final int MAX_GROUP_MEMBERS = 5000;

	/** Puerto de conexion LDAP * */
	int ldapPort = LDAPConnection.DEFAULT_PORT;
	/** Version del servidor LDAP */
	int ldapVersion = LDAPConnection.LDAP_V3;
	/** Usuario root de conexión LDAP */
	String loginDN;
	/** Password del usuario administrador cn=root,dc=caib,dc=es */
	String password;
	/** HOST donde se aloja LDAP */
	String ldapHost;
	/** ofuscador de claves SHA */
	MessageDigest digest;

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
	static Hashtable pool = new Hashtable();

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

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting LDAPAgente agent on {}", getDispatcher().getCodi(),
				null);
		loginDN = getDispatcher().getParam0();
		password = Password.decode(getDispatcher().getParam1()).getPassword();
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

		try {
			digest = MessageDigest.getInstance(hashType);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new InternalErrorException(
					"Unable to use SHA encryption algorithm ", e);
		}

	}


	/**
	 * Actualiza la contraseña del usuario. Genera la ofuscación SHA-1 y la
	 * asigna al atributo userpassword de la clase inetOrgPerson
	 * @param accountName 
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void updatePassword(String accountName, ExtensibleObjects objects, Password password,
			boolean mustchange) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {

		LDAPAttribute atributo;
		LDAPEntry ldapUser;

		for (ExtensibleObject object : objects.getObjects()) {
			String dn = vom.toString(object.getAttribute("dn"));
			if (dn != null) {

				boolean repeat = false;
				do {
					try {
						ldapUser = buscarUsuario(object); // ui puede ser nulo

						if (ldapUser == null) {
							// Generem un error perquè potser que l'usuari
							// encara
							// no esté donat d'alta al ldap [usuaris alumnes]:
							// u88683 27/01/2011
							updateObjects(accountName, objects);
							ldapUser = buscarUsuario(object);
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
							getConnection().modify(dn, mods);
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
	 * obtiene conexión con el directorio LDAP
	 * 
	 * @throws InternalErrorException
	 *             imposible conectar con el servidor LDAP
	 */
	@SuppressWarnings("unchecked")
	private LDAPConnection getConnection() throws InternalErrorException {
		LDAPConnection conn = (LDAPConnection) pool.get(getDispatcher()
				.getCodi());
		if (conn != null && !conn.isConnectionAlive()) {
			cerrarConexion();
			conn = null;
		}
		if (conn == null) { // Verifiquem que siga activa
			try {
				conn = new LDAPConnection();
				conn.connect(ldapHost, ldapPort);
				conn.bind(ldapVersion, loginDN, password.getBytes("UTF8"));
				pool.put(getDispatcher().getCodi(), conn);
			} catch (Exception e) {
				String msg = "getConnection(): Error en la conexión con LDAP. ["
						+ e.getMessage() + "]";
				log.warn(msg, e);
				throw new InternalErrorException(msg, e);
			}
		}
		return (conn);
	}

	/**
	 * Cierra la conexion con el directorio LDAP.
	 * 
	 * @throws InternalErrorException
	 *             imposible conectar con el servidor LDAP
	 */
	private void cerrarConexion() {
		LDAPConnection conn = (LDAPConnection) pool.get(getDispatcher()
				.getCodi());
		if (conn != null) {
			pool.remove(getDispatcher().getCodi());
			try {
				conn.disconnect();
			} catch (LDAPException e) {

			}
		}
	}

	public static final String escapeLDAPSearchFilter(String filter) {
		StringBuffer sb = new StringBuffer(); // If using JDK >= 1.5 consider
												// using StringBuilder
		for (int i = 0; i < filter.length(); i++) {
			char curChar = filter.charAt(i);
			switch (curChar) {
			case '\\':
				sb.append("\\5c");
				break;
			case '*':
				sb.append("\\2a");
				break;
			case '(':
				sb.append("\\28");
				break;
			case ')':
				sb.append("\\29");
				break;
			case '\u0000':
				sb.append("\\00");
				break;
			default:
				sb.append(curChar);
			}
		}
		return sb.toString();
	}
	/**
	 * Busca los datos de un usuario en el directorio LDAP
	 * 
	 * @param user
	 *            codigo del usuario
	 * @return LDAPEntry entrada del directorio LDAP
	 * @throws InternalErrorException
	 *             Error al buscar el usuario
	 */
	private LDAPEntry buscarUsuario(ExtensibleObject object) throws InternalErrorException {
		String dn = vom.toString(object.getAttribute("dn"));
		try {
			ExtensibleObjectMapping mapping = getMapping(object.getObjectType());
			String keyObject = mapping.getProperties().get("key");
			String keyValue = keyObject == null ? null :
				vom.toString(object.getAttribute(keyObject));
			String base = mapping.getProperties().get("baseDn");

			if (keyObject == null)
				return getConnection().read(dn);
			else
			{
				String objectClass = vom.toSingleString(object
						.getAttribute("objectClass"));
				String queryString = "(&(objectClass=" + objectClass
						+ ")("+keyObject+"=" + escapeLDAPSearchFilter(keyValue.toString())
						+ "))";
				log.info("Looking for objects: LDAP QUERY="
							+ queryString.toString() + " on " + base);
				LDAPSearchResults query = getConnection().search(base,
						LDAPConnection.SCOPE_SUB, queryString, null, false);
				while (query.hasMore()) {
					try {
						LDAPEntry entry = query.next();
						return entry;
					} catch (LDAPReferralException e) {
					}
				}

				return null;
			}
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
				return null;
			String msg = "buscarUsuario ('" + dn
					+ "'). Error al buscar el usuario. [" + e.getMessage()
					+ "]";
			log.warn(msg, e);
			cerrarConexion();
			throw new InternalErrorException(msg, e);
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
		synchronized (digest) {
			hash = passwordPrefix
					+ Base64.encodeBytes(
							digest.digest(password.getPassword().getBytes()),
							Base64.DONT_BREAK_LINES);
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
		else
		{
			return new String[] { vom.toString(obj) };
		}
	}

	private ExtensibleObjectMapping getMapping(String objectType) {
		for (ExtensibleObjectMapping map : objectMappings) {
			if (map.getSystemObject().equals(objectType))
				return map;
		}
		return null;
	}

	/**
	 * Añade los datos de un usuario al directorio LDAP
	 * @param accountName 
	 * 
	 * @param usuario
	 *            Informacion del usuario
	 * @throws InternalErrorException
	 *             Error al añadir el usuario al directorio LDAP
	 */
	public void updateObjects(String accountName, ExtensibleObjects objects)
			throws InternalErrorException {

		for (ExtensibleObject object : objects.getObjects()) {
			String dn = vom.toString(object.getAttribute("dn"));
			try {
				if (dn != null) {
					log.info("Updating object {}", dn, null);
					LDAPEntry entry = buscarUsuario(object);
					if (entry == null) {
						LDAPAttributeSet attributeSet = new LDAPAttributeSet();
						for (String attribute : object.getAttributes()) {
							String values[] = toStringArray(object.getAttribute(attribute));
							if (values != null && !"dn".equals(attribute))
							{
								attributeSet.add(new LDAPAttribute(attribute,values	));
							}
						}
						entry = new LDAPEntry(dn, attributeSet);
						getConnection().add(entry);
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
						for (String attribute : object.getAttributes()) {
							if (!"dn".equals(attribute) &&  !"objectClass".equals(attribute))
							{
								String[] value = toStringArray(object.getAttribute(attribute));
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
									modList.add(new LDAPModification(
											LDAPModification.REPLACE,
											new LDAPAttribute(attribute, value)));
								}
							}
						}
						LDAPModification[] mods = new LDAPModification[modList
								.size()];
						mods = new LDAPModification[modList.size()];
						mods = (LDAPModification[]) modList.toArray(mods);
						getConnection().modify(dn, mods);
						
						if (!entry.getDN().equalsIgnoreCase(dn)) {
							// Check if must rename
							boolean rename = true;
							ExtensibleObjectMapping mapping = getMapping(object
									.getObjectType());
							if (mapping != null) {
								rename = !"false".equalsIgnoreCase(mapping
										.getProperties().get("rename"));
							}
							if (rename) {
								int i = dn.indexOf(",");
								if (i > 0) {
									String parentName = dn.substring(i + 1);

									getConnection().rename(entry.getDN(), dn.substring(0, i),
											parentName, true);
								}
							}
						}
					}
				}
			} catch (Exception e) {
				String msg = "updating object : " + dn;
				log.warn(msg, e);
				throw new InternalErrorException(msg, e);
			}
		}
	}

	public void removeObjects(ExtensibleObjects objects)
			throws RemoteException, InternalErrorException {
		for (ExtensibleObject object : objects.getObjects()) {
			String dn = vom.toString(object.getAttribute("dn"));
			try {
				if (dn != null) {
					log.info("Updating object {}", dn, null);
					getConnection().delete(dn);
				}
			} catch (Exception e) {
				String msg = "updating object : " + dn;
				log.warn(msg, e);
				throw new InternalErrorException(msg, e);
			}
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
			throws RemoteException, InternalErrorException {
		String dn = vom.toString(objectQuery.getAttribute("dn"));
		StringBuffer buf = new StringBuffer ();
		for (String attribute : objectQuery.getAttributes()) {
			if (! attribute.equals("dn"))
			{
				String [] values = toStringArray(objectQuery.getAttribute(attribute));
				if (values.length > 0)
				{
					if (buf.length() == 0)
						buf.append ("(& ");
					if (values.length > 1)
						buf.append ("(| ");
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
		try {
			Collection<ExtensibleObject> objs = new LinkedList<ExtensibleObject>(); 
			LDAPSearchResults query = getConnection().search(dn, LDAPConnection.SCOPE_SUB, buf.toString(), null, false);
			while (query.hasMore())
			{
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
			}
			return objs;
		} catch (LDAPException e) {
			String msg = "updating object : " + dn;
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		}
		
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
	
	LinkedList<String> getSoffidAccounts (SoffidObjectType type) throws LDAPException, InternalErrorException
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
				sb.append ("(&");
				boolean any = false;
				String base = null;
				for (String att: dummySystemObject.getAttributes())
				{
					String value = vom.toSingleString(dummySystemObject.getAttribute(att));
					if ("dn".equals(att))
					{
						base = removeIncompleteComponentsFromBase(value);
					}
					else
					{
						if (value != null)
						{
							sb.append ("(")
								.append (att)
								.append("=")
								.append(value)
								.append(")");
							any = true;
						}
					}
				}
				
				sb.append(")");
				
				if (any && base != null)
				{
					LDAPConnection lc = getConnection();
					LDAPSearchConstraints oldConst = lc.getSearchConstraints();	// Save search constraints
					LDAPPagedResultsControl pageResult =
							new LDAPPagedResultsControl(100, false);

					do
					{
						LDAPSearchConstraints constraints = lc.getSearchConstraints();
						constraints.setControls(pageResult);
						lc.setConstraints(constraints);

						LDAPSearchResults searchResults = lc.search(base, LDAPConnection.SCOPE_SUB, sb.toString(), null, false);

						// Process results
						while (searchResults.hasMore())
						{
							LDAPEntry entry = searchResults.next();
							ExtensibleObject eo = parseEntry (entry, mapping);
							ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
							for (ExtensibleObject eo2: parsed.getObjects())
							{
								Account account = vom.parseAccount(eo2);
								if (account != null)
									accounts.add(account.getName());
							}
						}

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
					} while (pageResult.getCookie() != null);
					lc.getSearchConstraints().setControls(new LDAPControl[0]);

				}
			}
		}
		return accounts;

	}

	
	LinkedList<ExtensibleObject> getLdapObjects (SoffidObjectType type, String first, int count) throws LDAPException, InternalErrorException
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
				sb.append ("(&");
				boolean any = false;
				String base = null;
				for (String att: dummySystemObject.getAttributes())
				{
					String value = vom.toSingleString(dummySystemObject.getAttribute(att));
					if ("dn".equals(att))
					{
						base = removeIncompleteComponentsFromBase(value);
					}
					else
					{
						if (value != null)
						{
							sb.append ("(")
								.append (att)
								.append("=")
								.append(value)
								.append(")");
							any = true;
						}
					}
				}
				
				sb.append(")");
				
				if (any && base != null)
				{
					LDAPConnection lc = getConnection();
					LDAPSearchConstraints oldConst = lc.getSearchConstraints();	// Save search constraints
					LDAPPagedResultsControl pageResult =
							new LDAPPagedResultsControl(count, false);
			

					do
					{
						LDAPSearchConstraints constraints = lc.getSearchConstraints();
						constraints.setControls(pageResult);
						constraints.setMaxResults(0);
						lc.setConstraints(constraints);

						LDAPSearchResults searchResults = lc.search(base, LDAPConnection.SCOPE_SUB, sb.toString(), null, false);

						// Process results
						while (searchResults.hasMore())
						{
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
					} while (pageResult.getCookie() != null && count > 0);
					lc.getSearchConstraints().setControls(new LDAPControl[0]);
				}
			}
		}
		return objects;
	}

	private String removeIncompleteComponentsFromBase(String base) {
		if (base == null)
			return null;
		else if (base.endsWith("="))
		{
			base = base.substring(0, base.lastIndexOf(",")).trim();
		}
		if (base.endsWith(","))
			base = base.substring(0, base.length()-1);
		return base;
	}
	
	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		
		Set<String>accounts = new HashSet<String>();
		try {
			accounts.addAll(getSoffidAccounts(SoffidObjectType.OBJECT_USER));
			accounts.addAll(getSoffidAccounts(SoffidObjectType.OBJECT_ACCOUNT));
		} catch (LDAPException e) {
			cerrarConexion();
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

	}
	
	private ExtensibleObject findExtensibleUser (String userAccount) throws InternalErrorException
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
	
	private ExtensibleObject findUserByExample (ExtensibleObject example) throws InternalErrorException
	{
		// For each suitable mappping
		for (ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(example.getObjectType()))
			{
				// Generate system objects from source user
				ExtensibleObject systemObject = objectTranslator.generateObject(example, objectMapping, true);
				
				// Search object by dn
				LDAPEntry entry = buscarUsuario(systemObject);
				if (entry != null)
				{
					return parseEntry (entry, objectMapping);
				}
			}
		}
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		Set<String>roles = new HashSet<String>();
		try {
			Pattern constantPattern = Pattern.compile("\\s*\"(.*)\"\\s*");
			Pattern constantPattern2 = Pattern.compile("\\s*\"(.*)\"\\s*.*");
			for (ExtensibleObjectMapping mapping: objectMappings )
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
				{
					AttributeMapping attMapping = findAttribute(mapping, "objectType");
					AttributeMapping baseMapping = findAttribute(mapping, "dn");
						
					if (attMapping != null && baseMapping != null)
					{
						Matcher matcher = constantPattern.matcher(attMapping.getSoffidAttribute());
						if (matcher.matches())
						{
							Matcher matcher2 = constantPattern2.matcher(baseMapping.getSoffidAttribute());
							if (matcher2.matches())
							{
								String objectType=matcher.group(1).trim();
								String base= matcher2.group(1).trim();
								base = removeIncompleteComponentsFromBase(base);
									
								LDAPSearchResults found = getConnection().search(base, LDAPConnection.SCOPE_SUB, "(objectType="+objectType+")", null, true);
								while (found.hasMore())
								{
									LDAPEntry entry = found.next();
									ExtensibleObject eo = parseEntry (entry, mapping);
									ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
									for (ExtensibleObject parsedObject : parsed.getObjects())
									{
										Rol rol = vom.parseRol(parsedObject);
										if (rol != null)
											roles.add (rol.getNom());
									}
								}
							}
						}
					}
				}
			}
		} catch (LDAPException e) {
			cerrarConexion();
			throw new InternalErrorException ("Error getting accounts list", e);
		}
		return new LinkedList<String>(roles);
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
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
				LDAPEntry entry = buscarUsuario(systemObject);
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
	}

	public List<Rol> getAccountRoles(String userAccount)
			throws RemoteException, InternalErrorException {
		List<Rol> roles;
		try {
			roles = new LinkedList();
			if (!populateRolesFromUser(userAccount, roles))
				populateRolesFromRol(userAccount, roles);
		} catch (LDAPException e) {
			cerrarConexion();
			throw new InternalErrorException("Error accessing LDAP", e);
		}
		return roles;
	}

	private boolean populateRolesFromUser(String userAccount, List<Rol> roles) throws InternalErrorException 
	{
		boolean found = true;
		ExtensibleObject userObject = findExtensibleUser(userAccount);
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
		
		return found;
	}

	private boolean populateRolesFromRol(String userAccount, List<Rol> roles) throws LDAPException, InternalErrorException 
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
		
		// Generate a dummy object to perform query
		ExtensibleObjects systemObjects = objectTranslator.generateObjects(rolObject);
		for (ExtensibleObject systemObject: systemObjects.getObjects())
		{
			StringBuffer sb = new StringBuffer();
			sb.append ("(&");
			boolean any = false;
			String base = null;
			for (String att: systemObject.getAttributes())
			{
				String value = vom.toSingleString(systemObject.getAttribute(att));
				if ("dn".equals(att))
				{
					base = removeIncompleteComponentsFromBase(value);
				}
				else
				{
					if (value != null)
					{
						sb.append ("(")
							.append (att)
							.append("=")
							.append(value)
							.append(")");
						any = true;
					}
				}
			}
			sb.append(")");
			if (any && base != null)
			{
				LDAPSearchResults search = getConnection().search(base, LDAPConnection.SCOPE_SUB, sb.toString(), null, false);
				while (search.hasMore())
				{
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
					
				}
			}
		}

		return found;
	}

	public void updateUser(String userName, Usuari userData)
			throws RemoteException, InternalErrorException {
		Account account = new Account();
		account.setName(userName);
		account.setDescription(userData.getFullName());
		account.setDisabled(false);
		account.setDispatcher(getDispatcher().getCodi());
		ExtensibleObjects objects = objectTranslator.generateObjects(new UserExtensibleObject(account, userData, getServer()));
		updateObjects(userName, objects);
	}

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		Account account = new Account();
		account.setName(accountName);
		account.setDescription(description);
		account.setDisabled(false);
		account.setDispatcher(getDispatcher().getCodi());
		ExtensibleObjects objects = objectTranslator.generateObjects(new AccountExtensibleObject(account, getServer()));
		updateObjects(accountName, objects);
	}

	public void removeUser(String userName) throws RemoteException,
			InternalErrorException {
		Account account = getServer().getAccountInfo(userName, getCodi());
		ExtensibleObjects objects;
		if (account == null)
		{
			account = new Account();
			account.setName(userName);
			account.setDescription(userName);
			account.setDisabled(true);
			account.setDispatcher(getDispatcher().getCodi());
			objects = objectTranslator.generateObjects(new AccountExtensibleObject(account, getServer()));
			removeObjects(objects);
		}
		else
		{
			try {
				Usuari user = getServer().getUserInfo(userName, getDispatcher().getCodi());
				objects = objectTranslator.generateObjects(new UserExtensibleObject(account, user, getServer()));
			} catch (UnknownUserException e) {
				objects = objectTranslator.generateObjects(new AccountExtensibleObject(account, getServer()));
			}
			updateObjects(userName, objects);
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
		updatePassword(userName, objects, password, mustchange);
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
		if (!getCodi().equals(rol.getBaseDeDades()))
			return;
		ExtensibleObjects objects = objectTranslator.generateObjects(new RoleExtensibleObject(rol, getServer()));
		updateObjects(null, objects);
	}

	public void removeRole(String rolName, String dispatcher)
			throws RemoteException, InternalErrorException {
		Rol rol = new Rol();
		rol.setNom(rolName);
		rol.setBaseDeDades(dispatcher);
		ExtensibleObjects objects = objectTranslator.generateObjects(new RoleExtensibleObject(rol, getServer()));
		removeObjects(objects);
	}

	private String firstChange = null;
	public Collection<AuthoritativeChange> getChanges()
			throws InternalErrorException {
		Collection<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		try {
			LinkedList<ExtensibleObject> objects = getLdapObjects(SoffidObjectType.OBJECT_USER, firstChange, 150);
			if (objects.isEmpty())
			{
				firstChange = null;
				objects = getLdapObjects(SoffidObjectType.OBJECT_USER, firstChange, 10);
			}
			
			for (ExtensibleObject ldapObject: objects)
			{
				firstChange = vom.toSingleString(ldapObject.getAttribute("dn"));
				ExtensibleObjects parsedObjects = objectTranslator.parseInputObjects(ldapObject);
				for (ExtensibleObject object: parsedObjects.getObjects())
				{
					Usuari user = vom.parseUsuari(object);
					if (user != null)
					{
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
								attributesMap.put((String)attributeName, vom.toSingleton(((Map)attributes).get(attributeName)));
							}
							change.setAttributes(attributesMap);
						}
						
						changes.add(change);
						
					}
				}
				
			}
		} catch (LDAPException e) {
			cerrarConexion();
			throw new InternalErrorException ("Error getting accounts list", e);
		}
		return changes;
	}

	public void commitChange(AuthoritativeChangeIdentifier id)
			throws InternalErrorException {
	}
}
	