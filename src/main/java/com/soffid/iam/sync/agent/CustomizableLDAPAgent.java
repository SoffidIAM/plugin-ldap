package com.soffid.iam.sync.agent;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import javax.management.Attribute;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSchema;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSchema;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;
import com.soffid.iam.api.Group;
import com.soffid.iam.api.HostService;
import com.soffid.iam.api.PasswordValidation;
import com.soffid.iam.sync.intf.GroupMgr;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.comu.AttributeDirection;
import es.caib.seycon.ng.comu.AttributeMapping;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.LlistaCorreu;
import es.caib.seycon.ng.comu.ObjectMapping;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.GroupExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.MailListExtensibleObject;
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
import es.caib.seycon.ng.sync.intf.MailAliasMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
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

public class CustomizableLDAPAgent extends Agent implements
		ExtensibleObjectMgr, UserMgr, ReconcileMgr2, RoleMgr,
		GroupMgr,
		MailAliasMgr,
		AuthoritativeIdentitySource2 {
	private final class CaseComparator implements Comparator {
		@Override
		public int compare(Object o1, Object o2) {
			if (o1 == null && o2 == null) return 0;
			if (o1 == null) return -1;
			if (o2 == null) return +1;
			return o1.toString().toLowerCase().compareTo(o2.toString().toLowerCase());
		}
	}

	boolean ssl;
	ValueObjectMapper vom = new ValueObjectMapper();

	protected ObjectTranslator objectTranslator = null;

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

	protected Collection<ExtensibleObjectMapping> objectMappings;
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

	static HashMap<String, LDAPPool> pools = new HashMap<String, LDAPPool>();

	protected LDAPPool pool;
	private HashMap<String, String> extendedAttributes = new HashMap<>();
	private boolean smartGrant;

	@Override
	public void init() throws InternalErrorException {
		loginDN = getDispatcher().getParam0();
		password = Password.decode(getDispatcher().getParam1());
		log.info("Starting LDAPAgente agent on {}: {}", getDispatcher()
				.getCodi(), loginDN);
		// password = params[1];
		ssl = "true".equals(getDispatcher().getParam9());
		ldapHost = getDispatcher().getParam2();
		int i = ldapHost.lastIndexOf(':');
		if (i > 0 ) {
			ldapPort = Integer.parseInt(ldapHost.substring(i+1));
			ldapHost = ldapHost.substring(0, i);
		} else {
			ldapPort = ssl ? LDAPConnection.DEFAULT_SSL_PORT: LDAPConnection.DEFAULT_PORT; 
		}
		passwordAttribute = getDispatcher().getParam3();
		if (passwordAttribute == null || passwordAttribute.trim().isEmpty())
			passwordAttribute = "userPassword";
		hashType = getDispatcher().getParam4();
		if (hashType == null)
			hashType = "SHA";
		passwordPrefix = getDispatcher().getParam5();
		if (passwordPrefix == null)
			hashType = "{" + hashType + "}";
		baseDN = getDispatcher().getParam7();

		debugEnabled = "true".equals(getDispatcher().getParam8());
		log.info("Debug mode: "+debugEnabled);
		try {
			if (getDispatcher().getParam6() == null
					|| getDispatcher().getParam6().trim().length() == 0)
				pagesize = 100;
			else
				pagesize = Integer.parseInt(getDispatcher().getParam6());
		} catch (NumberFormatException e) {
			throw new InternalErrorException("Wrong numeric value "
					+ getDispatcher().getParam6());
		}
		try {
			if (hashType != null && hashType.length() > 0)
				digest = MessageDigest.getInstance(hashType);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new InternalErrorException(
					"Unable to use SHA encryption algorithm ", e);
		}

		byte[] data = getDispatcher().getBlobParam();
		if (data != null)
		{
			String t;
			try {
				t = new String ( data,"UTF-8");
				if (t != null)
				{
					for (String tag: t.split("&")) {
						int p = tag.indexOf("=");
						String attribute;
						String v;
						try {
							attribute = p < 0 ? tag: java.net.URLDecoder.decode(tag.substring(0, p), "UTF-8");
							v = p > 0 ? java.net.URLDecoder.decode(tag.substring(p+1), "UTF-8"): null;
							extendedAttributes .put(attribute, v);
						} catch (UnsupportedEncodingException e) {
						}
					}
				}
			} catch (UnsupportedEncodingException e1) {
			} 
		}

		smartGrant = "true".equals(extendedAttributes.get("grantStrategy"));
		
		pool = pools.get(getCodi());
		if (pool == null) {
			pool = new LDAPPool();
			pools.put(getCodi(), pool);
		}
		pool.setSsl(ssl);
		pool.setBaseDN(baseDN);
		pool.setLdapHost(ldapHost);
		pool.setLdapPort(ldapPort);
		pool.setLdapVersion(ldapVersion);
		pool.setLoginDN(loginDN);
		pool.setPassword(password);
		
		try {
			pool.getConnection();
		} catch (Exception e) {
			throw new InternalErrorException("Error connecting to "+ldapHost+":"+ldapPort, e);
		}
		pool.returnConnection();
	}

	/**
	 * Actualiza la contraseña del usuario. Genera la ofuscación SHA-1 y la
	 * asigna al atributo userpassword de la clase inetOrgPerson
	 * 
	 * @param accountName
	 * @throws Exception
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void updatePassword(String accountName, ExtensibleObjects objects,
			ExtensibleObject soffidObject,
			Password password, boolean mustchange) throws Exception {

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
							updateObjects(accountName, objects, soffidObject);
							ldapUser = buscarUsuario(object);
						}

						ArrayList modList = new ArrayList();
						if (ldapUser != null) {
							String hash = getHashPassword(password);
							object.put(passwordAttribute, hash);
							soffidObject.put("password", password);
							soffidObject.put("mustChange", mustchange);
							atributo = new LDAPAttribute(passwordAttribute,
									hash);
							modList.add(new LDAPModification(
									LDAPModification.REPLACE, atributo));
							LDAPModification[] mods = new LDAPModification[modList
									.size()];
							mods = new LDAPModification[modList.size()];
							mods = (LDAPModification[]) modList.toArray(mods);
							debugModifications("Modifying password ", ldapUser.getDN(), mods);
							if (prePassword(soffidObject, object, ldapUser)) {
								try {
									pool.getConnection().modify(dn, mods);
								} finally {
									pool.returnConnection();
								}
								log.info(
										"UpdateUserPassword - setting password for user {}",
										dn, null);
								postPassword(soffidObject, object, ldapUser);
							}
						}
						return;
					} catch (LDAPException e) {
						if (e.getResultCode() == LDAPException.UNWILLING_TO_PERFORM
								&& !repeat) {
							updateObjects(accountName, objects, soffidObject);
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
	 * @throws Exception
	 */
	protected LDAPEntry buscarUsuario(ExtensibleObject object) throws Exception {
		String dn = vom.toString(object.getAttribute("dn"));
		LDAPConnection conn = pool.getConnection();
		try {
			ExtensibleObjectMapping mapping = getMapping(object.getObjectType());
			String keyObject = mapping.getProperties().get("key");
			String keyValue = keyObject == null ? null : vom.toString(object
					.getAttribute(keyObject));

			if (keyObject == null)
			{
				if (debugEnabled)
					log.info("No key property defined. Searching dn "+dn);
				return conn.read(dn);
			}
			else 
			{
				Object oc = object.getAttribute("objectClass");
				String queryString = "(&";
				if (oc instanceof String[])
				{
					for (String objectClass: (String[])oc)
					{
						queryString = queryString + "(objectClass=" + objectClass + ")";						
					}
				} else {
					queryString = queryString + "(objectClass=" + vom.toSingleString(oc) + ")";

				}
				queryString = queryString +
						"("+ keyObject + "="
						+ escapeLDAPSearchFilter(keyValue.toString()) + "))";
				log.info("Looking for objects: LDAP QUERY="
						+ queryString.toString() + " on " + baseDN);
				LDAPSearchResults query = conn.search(baseDN,
						LDAPConnection.SCOPE_SUB, queryString, null, false);
				while (query.hasMore()) {
					try {
						LDAPEntry entry = query.next();
						return entry;
					} catch (LDAPReferralException e) {
					}
				}
				log.info("Not found");
				return null;
			}
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT ||
					e.getResultCode() == LDAPException.INVALID_DN_SYNTAX)
				return null;
			String msg = "buscarUsuario ('" + dn
					+ "'). Error al buscar el usuario. [" + e.getMessage()
					+ "]";
			log.warn(msg, e);
			throw e;
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
		if (password == null)
			return null;
		else if (digest == null )
			hash = password.getPassword();
		else {
			synchronized (digest) {
				hash = passwordPrefix
						+ Base64.encodeBytes(digest.digest(password
								.getPassword().getBytes()),
								Base64.DONT_BREAK_LINES);
			}
		}
		return hash;
	}

	private Object[] toStringArray(Object obj) {
		if (obj == null)
			return null;
		else if (obj instanceof Collection) {
			return toStringArray(((Collection)obj).toArray());
		}
		else if (obj instanceof String[]) {
			return (String[]) obj;
		} else if (obj instanceof byte[][]) {
			return (byte[][])obj;
		} else if (obj instanceof byte[]) {
			return new byte[][]{(byte[])obj};
		} else if (obj instanceof Object[]) {
			return vom.toStringArray((Object[]) obj);
		} else if ("".equals(obj))
			return null;
		else {
			return new String[] { vom.toString(obj) };
		}
	}

	protected ExtensibleObjectMapping getMapping(String objectType) {
		for (ExtensibleObjectMapping map : objectMappings) {
			if (map.getSystemObject().equals(objectType))
				return map;
		}
		return null;
	}

	/**
	 * Añade los datos de un usuario al directorio LDAP
	 * 
	 * @param accountName
	 * 
	 * @param usuario
	 *            Informacion del usuario
	 * @throws Exception
	 */
	public void updateObjects(String accountName, ExtensibleObjects objects, ExtensibleObject soffidObject)
			throws Exception {
		for (ExtensibleObject obj : objects.getObjects()) {
			String dn = vom.toString(obj.getAttribute("dn"));
			try {
				if (dn != null) {
					log.info("Updating object {}", dn, null);
					LDAPEntry entry = buscarUsuario(obj);
					if (entry == null) {
						Object objectClass = obj.getAttribute("objectClass");
						if (objectClass != null) {
							if (objectClass.toString().toLowerCase().contains("groupofuniquenames") && 
									obj.getAttribute("uniqueMember") == null)
								obj.put("uniqueMember", "cn=nobody,"+baseDN);
							if (objectClass.toString().toLowerCase().contains("groupofnames") && 
									obj.getAttribute("member") == null)
								obj.put("member", "cn=nobody,"+baseDN);
							if (objectClass.toString().toLowerCase().contains("posixgroup") && 
									obj.getAttribute("memberUid") == null) 
								obj.put("memberuid", "-1");
						}
						if (debugEnabled) {
							log.info("================================================");
							debugObject("Creating object", obj, "  ");
						} 
						if (preInsert(soffidObject, obj))
						{
							LDAPAttributeSet attributeSet = new LDAPAttributeSet();
							for (String attribute : obj.getAttributes()) {
								Object[] valuesObject = toStringArray(obj.getAttribute(attribute));
								if (valuesObject != null && !"dn".equals(attribute)) {
									LDAPAttribute att;
									att = populateAttribute(attribute, valuesObject);
									attributeSet.add(att);
									if (debugEnabled)
										debugAttribute(LDAPModification.ADD,
												att);
								}
							}
							if (debugEnabled)
								log.info("================================================");
							String[] splitDn = splitDN(dn);
							if (splitDn.length > 0) {
								createParents(splitDn, 1);
							}
							entry = new LDAPEntry(dn, attributeSet);
							try {
								pool.getConnection().add(entry);
							} finally {
								pool.returnConnection();

							}
							if (accountName != null) {
								Password p = getServer().getAccountPassword(
										accountName, getCodi());
								if (p != null) {
									updatePassword(accountName, objects, soffidObject, p,
											false);
								} else {
									p = getServer().generateFakePassword(
											accountName, getCodi());
									if (p != null)
										updatePassword(accountName, objects, soffidObject, p,
											true);
								}
							}
							postInsert(soffidObject, obj, entry);
						}
					} else {
						if (debugEnabled) {
							log.info("================================================");
							debugObject("Updating object "+entry.getDN(), obj, "  ");
							log.info("================================================");
							debugEntry("Current value ", entry.getDN(), entry.getAttributeSet());
							log.info("================================================");
						}
						if (preUpdate(soffidObject, obj, entry))
						{
							LinkedList<LDAPModification> modList = new LinkedList<LDAPModification>();
							for (String attribute : obj.getAttributes()) {
								if (!"dn".equals(attribute)
										&& !"objectClass".equals(attribute)) {
									Object v = obj.getAttribute(attribute);
									Object[] value = toStringArray(obj.getAttribute(attribute));
									if (value != null && 
											(value instanceof String[]) &&
											((String[])value).length == 1 &&
											((String[])value)[0].trim().isEmpty())
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
												populateAttribute(attribute, value)));
									} else if (value != null
											&& entry.getAttribute(attribute) != null) {
										if (v instanceof byte[][] )
											modList.add(new LDAPModification(
													LDAPModification.REPLACE,
													populateAttribute(attribute, value)));
										else {
											updateAttribute(entry, attribute, value, modList);
										}
									}
								}
							}

							if (modList.size() > 0) {
								doModify(entry, modList);
							}
							if (!entry.getDN().equalsIgnoreCase(dn)) {
								// Check if must rename
								boolean rename = true;
								ExtensibleObjectMapping mapping = getMapping(obj
										.getObjectType());
								if (mapping != null) {
									rename = !"false".equalsIgnoreCase(mapping
											.getProperties().get("rename"));
								}
								if (rename) {
									if (debugEnabled)
										log.info("Renaming from "+entry.getDN()+" to "+dn);
									String[] parts = splitDN(dn);
									if (parts.length > 0) {
										createParents(parts, 1);

										LDAPConnection conn = pool.getConnection();
										try {
											conn.rename(entry.getDN(),
													parts[0], joinDnParts(parts, 1),
													true);
										} finally {
											pool.returnConnection();
										}
									}
								}
							}
							postUpdate(soffidObject, obj, entry);
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

	private void doModify(LDAPEntry entry, List<LDAPModification> modList)
			throws Exception {
		LDAPModification[] mods = new LDAPModification[modList
				.size()];
		mods = new LDAPModification[modList.size()];
		mods = (LDAPModification[]) modList
				.toArray(mods);
		debugModifications("Modifying", entry.getDN(), mods);
		LDAPConnection conn = pool.getConnection();
		LDAPConstraints c = conn.getConstraints();
		c.setTimeLimit(60000);
		conn.setConstraints(c);
		try {
			conn.modify(entry.getDN(), mods);
		} finally {
			pool.returnConnection();
		}
	}

	private void updateAttribute(LDAPEntry entry, String attribute, Object[] value,
			LinkedList<LDAPModification> modList) throws Exception {
		if (smartGrant && 
				("member".equals(attribute) || 
				 "uniqueMember".equals(attribute) ||
				 "memberUid".equalsIgnoreCase(attribute))) {
			return; // Ignore changes to these attributes
		}
		boolean update = false;
		if (value.length < 10) {
			String[] oldvalue = entry
					.getAttribute(attribute)
					.getStringValueArray();
			if (value.length != oldvalue.length)
				update = true;
			else {
				for (int i = 0; i < value.length; i++) {
					if (!value[i]
							.equals(oldvalue[i])) {
						update = true;
						break;
					}
				}
			}
			if (update) 
				modList.add(new LDAPModification(
						LDAPModification.REPLACE,
						populateAttribute(
								attribute,
								value)));
		} else {
			incrementalUpdateAttribute(entry, attribute, value, modList);
		}
	}

	private void incrementalUpdateAttribute(LDAPEntry entry, String attribute, Object[] value,
			LinkedList<LDAPModification> modList) throws Exception {
		boolean nocase = attribute.equalsIgnoreCase("member") || attribute.equalsIgnoreCase("uniquemember");
		List<Object> adds = new LinkedList<Object>();
		List<Object> removes = new LinkedList<Object>();
		if (nocase) 
			Arrays.sort(value, new CaseComparator());
		else
			Arrays.sort(value);
		
		if (debugEnabled) log.info("Computing delta changes for "+attribute);
		String[] oldvalue = entry
				.getAttribute(attribute)
				.getStringValueArray();
		if (nocase) 
			Arrays.sort(oldvalue, new CaseComparator());
		else
			Arrays.sort(oldvalue);
		for ( int i = 0, j = 0; i < value.length || j < oldvalue.length; ) {
			if (i < value.length && j < oldvalue.length) {
				if (debugEnabled) log.info("Comparing OLD: "+oldvalue[j].toString());
				if (debugEnabled) log.info("Comparing NEW: "+value[i].toString());
				int c = nocase ? oldvalue[j].toString().toLowerCase().compareTo(value[i].toString().toLowerCase()) :
						oldvalue[j].toString().compareTo(value[i].toString());
				if ( c == 0 ) { // Skip both
					i ++;
					j ++;
					if (debugEnabled) log.info("Keeping value");
				}
				else if (c < 0 ) { // oldvalue is lower
					if (debugEnabled) log.info("To Remove "+oldvalue[j]);
					removeValue(entry, attribute, oldvalue[j++]);
				} else { // oldvalue is greater
					if (debugEnabled) log.info("To Add "+value[i]);
					addValue(entry, attribute, value[i++].toString());
				}
			}
			else if (i < value.length) {
				if (debugEnabled) log.info("To Add "+value[i]);
				addValue(entry, attribute, value[i++].toString());
			}
			else {
				if (debugEnabled) log.info("To Remove "+oldvalue[j]);
				removeValue(entry, attribute, oldvalue[j++]);
			}
		}
	}

	private void removeValue(LDAPEntry entry, String attribute, String value) throws Exception {
		List<LDAPModification> l = Collections.singletonList(
				new LDAPModification(LDAPModification.DELETE, new LDAPAttribute(attribute, value)) );
		doModify(entry, l);
	}

	private void addValue(LDAPEntry entry, String attribute, String value) throws Exception {
		List<LDAPModification> l = Collections.singletonList(
				new LDAPModification(LDAPModification.ADD, new LDAPAttribute(attribute, value)) );
		try {
			doModify(entry, l);
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
				// Ignore
			}
			else
			{
				throw e;
			}
		}
	}

	protected LDAPAttribute populateAttribute(String attribute, Object[] valuesObject) {
		LDAPAttribute att;
		if (valuesObject instanceof byte[][]) {
			att = new LDAPAttribute(attribute) ;
			for (byte[] data: (byte[][])valuesObject)
				att.addValue(data);
		}
		else
			att = new LDAPAttribute(attribute, (String[]) valuesObject);
		return att;
	}

	public void removeObjects(ExtensibleObjects objects, ExtensibleObject soffidObject) throws Exception {
		LDAPConnection conn = pool.getConnection();
		try {
			for (ExtensibleObject object : objects.getObjects()) {
				try {
					LDAPEntry entry = buscarUsuario(object);
					if ( entry != null)
					{
						if (debugEnabled)
							debugEntry("Object to remove", entry.getDN(), entry.getAttributeSet());
						if (preDelete(soffidObject, entry))
						{
							conn.delete(entry.getDN());
							postDelete(soffidObject, entry);
						} 
					}
				} catch (LDAPException e) {
					String msg = "deleting object ";
					log.warn(msg, e);
					throw new InternalErrorException(msg, e);
				} catch (Exception e) {
					String msg = "deleting object ";
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
			if (ssl)
				conn = new LDAPConnection(new LDAPJSSESecureSocketFactory());
			else
				conn = new LDAPConnection();
			conn.connect(ldapHost, ldapPort);
			conn.bind(ldapVersion, loginDN,
					password.getPassword().getBytes("UTF8"));
			conn.disconnect();
			return true;
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.INSUFFICIENT_ACCESS_RIGHTS
					|| e.getResultCode() == LDAPException.INVALID_CREDENTIALS)
				return false;
			else
				throw new InternalErrorException("Error connecting to LDAP", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException("Error connecting to LDAP", e);
		}
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		this.objectMappings = objects;
		objectTranslator = new ObjectTranslator(getDispatcher(), getServer(),
				objectMappings);
		objectTranslator.setObjectFinder(new LDAPObjectFinder(this));

	}

	public Collection<ExtensibleObject> findObjects(ExtensibleObject objectQuery)
			throws Exception {
		LDAPConnection conn = pool.getConnection();
		try {
			StringBuffer buf = new StringBuffer();
			buildQuery(objectQuery, buf);
			if (debugEnabled)
				log.info("Performing query " + buf.toString());
			try {
				Collection<ExtensibleObject> objs = new LinkedList<ExtensibleObject>();
				LDAPSearchResults query = conn.search(baseDN,
						LDAPConnection.SCOPE_SUB, buf.toString(), null, false);
				while (query.hasMore()) {
					try {
						LDAPEntry entry = query.next();
						ExtensibleObject obj = new ExtensibleObject();
						obj.setAttribute("dn", entry.getDN());
						for (Object attrName : entry.getAttributeSet()) {
							LDAPAttribute attribute = entry
									.getAttribute((String) attrName);
							if (attribute.getStringValueArray().length == 0)
								obj.setAttribute((String) attrName,
										attribute.getStringValue());
							else
								obj.setAttribute((String) attrName,
										attribute.getStringValueArray());
						}
						objs.add(obj);
					} catch (LDAPException e) {
						if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
							break;
						else
							throw e;
					}
				}
				return objs;
			} catch (LDAPException e) {
				String msg = "error search objects : " + baseDN + ": "
						+ buf.toString();
				log.warn(msg, e);
				throw new InternalErrorException(msg, e);
			}
		} finally {
			pool.returnConnection();
		}

	}

	private boolean buildQuery(ExtensibleObject objectQuery, StringBuffer buf) {
		boolean any = false;
		int attributes = 0;
		for (String attribute : objectQuery.getAttributes()) {
			if (!attribute.equals("dn")) {
				Object[] values = toStringArray(objectQuery
						.getAttribute(attribute));
				if (values != null && values.length > 0) {
					any = true;
					attributes ++;
					if (values.length > 1)
						buf.append("(|");
					for (Object value : values) {
						buf.append("(").append(attribute).append("=")
								.append(escapeLDAPSearchFilter(value.toString()))
								.append(")");
					}
					if (values.length > 1)
						buf.append(")");
				}
			}
		}

		if (attributes > 1)
		{
			buf.insert(0, "(&");
			buf.append(")");
		}
		
		return any;
	}

	AttributeMapping findAttribute(ExtensibleObjectMapping objectMapping,
			String attribute) {
		for (AttributeMapping attMapping : objectMapping.getAttributes()) {
			if (attMapping.getSystemAttribute().equals(attribute)
					&& (attMapping.getDirection().equals(
							AttributeDirection.OUTPUT) || attMapping
							.getDirection().equals(
									AttributeDirection.INPUTOUTPUT))) {
				return attMapping;
			}
		}
		return null;
	}

	LinkedList<String> getSoffidAccounts(SoffidObjectType type)
			throws Exception {
		LDAPConnection conn;
		conn = pool.getConnection();
		try {
			LinkedList<String> accounts = new LinkedList<String>();

			ExtensibleObject dummySoffidObj = new ExtensibleObject();
			dummySoffidObj.setObjectType(type.getValue());

			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(type)) {
					ExtensibleObject dummySystemObject = objectTranslator
							.generateObject(dummySoffidObj, mapping, true);

					StringBuffer sb = new StringBuffer();
					boolean any = buildQuery(dummySystemObject, sb);
					if (debugEnabled)
						log.info("Performing query " + sb.toString());

					if (any) {
						if (debugEnabled)
							log.info("Executing query "+sb.toString()+" on "+baseDN);
						LDAPSearchConstraints oldConst = conn
								.getSearchConstraints(); // Save search
															// constraints
						LDAPPagedResultsControl pageResult = null;
						if (pagesize > 0) {
							log.info("Page size = "+pagesize);
							pageResult = new LDAPPagedResultsControl(pagesize,
									false);
						}

						do {
							LDAPSearchConstraints constraints = conn
									.getSearchConstraints();
							if (pageResult != null) {
								log.info("Setting pageResult cooking "+pageResult.getCookie());
								constraints.setControls(pageResult);
							}
							constraints.setMaxResults(0);
//							conn.setConstraints(constraints);
							conn.setSocketTimeOut(1200000); // Twenty minutes
							String key = mapping.getProperties().get("key");

							LDAPSearchResults searchResults = conn.search(
									baseDN, LDAPConnection.SCOPE_SUB,
									sb.toString(), key == null ? null: new String[] {key}, false,
									constraints);

							log.info("Searching ");
							if (pageResult != null)
								log.info("Cookie: "+pageResult.getCookie());
							// Process results
							while (searchResults.hasMore()) {
								try {
									LDAPEntry entry = searchResults.next();
									debugEntry("Got object", entry.getDN(), entry.getAttributeSet());
									ExtensibleObject eo = parseEntry(conn, entry,
											mapping);
									ExtensibleObjects parsed = objectTranslator
											.parseInputObjects(eo);
									for (ExtensibleObject eo2 : parsed
											.getObjects()) {
										debugObject("Translated to", eo2, "  ");
										Account account = vom.parseAccount(eo2);
										if (account != null)
											accounts.add(account.getName());
									}
								} catch (LDAPException e) {
									if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
										break;
									else if (e.getResultCode() == LDAPException.UNWILLING_TO_PERFORM) {
										log.warn("Error recopilando cuentas", e);
									}
									else
										throw e;
								}
							}

							if (pageResult != null) {
								LDAPControl responseControls[] = searchResults
										.getResponseControls();
								pageResult.setCookie(null); // in case no cookie
															// is returned we
															// need
															// to step out of
															// do..while

								if (responseControls != null) {
									for (int i = 0; i < responseControls.length; i++) {
										if (responseControls[i] instanceof LDAPPagedResultsResponse) {
											LDAPPagedResultsResponse response = (LDAPPagedResultsResponse) responseControls[i];
											log.info("Got result cookie "+response.getCookie());
											pageResult.setCookie(response.getCookie());
										}
									}
								}
							}
						} while (pageResult != null
								&& pageResult.getCookie() != null 
								&& pagesize > 0);
						conn.getSearchConstraints().setControls(
								new LDAPControl[0]);
					}
				}
			}
			return accounts;
		} finally {
			pool.returnConnection();
		}

	}

	private void createParents(String[] parts, int p) throws Exception {
		String dn = joinDnParts(parts, p);
		if (dn == null || dn.equals(baseDN))
			return;

		boolean found = false;
		try {
			pool.getConnection().read(dn);
			found = true;
		} catch (LDAPReferralException e) {
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.NO_SUCH_OBJECT) {
				throw e;
			}
		} finally {
			pool.returnConnection();
		}

		if (!found) {
			createParents(parts, p+1);
			LDAPAttributeSet attributeSet = new LDAPAttributeSet();
			if (dn.toLowerCase().startsWith("ou=")) {
				attributeSet.add(new LDAPAttribute("objectclass",
						"organizationalUnit"));
				String name = parts[p].substring(3);
				attributeSet.add(new LDAPAttribute("ou", name));
			} else {
				throw new InternalErrorException("Unable to create object "
						+ dn);
			}
			LDAPEntry entry = new LDAPEntry(dn, attributeSet);
			try {
				log.info("Creating " + dn);
				pool.getConnection().add(entry);
			} finally {
				pool.returnConnection();
			}
		}
	}

	protected String joinDnParts(String[] parts, int p) {
		String dn = null;
		for (int i = p; i < parts.length; i++) {
			if (dn == null) dn = parts[i];
			else dn = dn + ","+parts[i];
		}
		return dn;
	}

	LinkedList<ExtensibleObject> getLdapObjects(SoffidObjectType type,
			String first, String nextChange, int count) throws LDAPException,
			InternalErrorException {

		LDAPConnection conn;
		try {
			conn = pool.getConnection();
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to LDAP Server",
					e1);
		}
		try {
			ExtensibleObject dummySoffidObj = new ExtensibleObject();
			LinkedList<ExtensibleObject> objects = new LinkedList<ExtensibleObject>();
			dummySoffidObj.setObjectType(type.getValue());

			boolean start = first == null;

			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(type)) {
					ExtensibleObject dummySystemObject = objectTranslator
							.generateObject(dummySoffidObj, mapping, true);
					

					StringBuffer sb = new StringBuffer();
					boolean any = buildQuery(dummySystemObject, sb);

					if (any) {
						if (debugEnabled)
							log.info("Performing query " + sb.toString());
						String att = mapping.getProperties().get("modifyTimestamp");
						if (att != null && nextChange != null) {
							sb.insert(0, "(&");
							sb.append("("+att+">="+nextChange+"))");
						}
						if (debugEnabled)
							log.info("Performing query " + sb.toString());
						LDAPConnection lc = conn;
						LDAPSearchConstraints oldConst = lc
								.getSearchConstraints(); // Save search
															// constraints
						LDAPPagedResultsControl pageResult = null;
						if (count > 0)
							pageResult = new LDAPPagedResultsControl(count,
									false);

						do {
							LDAPSearchConstraints constraints = lc
									.getSearchConstraints();
							if (pageResult != null)
								constraints.setControls(pageResult);
							constraints.setMaxResults(0);
//							lc.setConstraints(constraints);

							log.debug("Searching for " + sb.toString() + " on "
									+ baseDN);

							LDAPSearchResults searchResults = lc.search(baseDN,
									LDAPConnection.SCOPE_SUB, sb.toString(),
									null, false,
									constraints);

							// Process results
							while (searchResults.hasMore()) {
								try {
									LDAPEntry entry = searchResults.next();
									log.info("Read object "+entry.getDN());
									if (!start) {
										if (entry.getDN().equals(first))
											start = true;
									} else {
										ExtensibleObject eo = parseEntry(conn, entry,
												mapping);
										objects.add(eo);
										if (--count == 0)
											break;
									}
								} catch (LDAPException e) {
									if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
										log.warn("Got exception no such object", e);
										break;
									}
									else
										throw e;
								}
							}

							if (pageResult != null) {
								LDAPControl responseControls[] = searchResults
										.getResponseControls();
								pageResult.setCookie(null); // in case no cookie
															// is returned we
															// need
								if (responseControls != null) {
									for (int i = 0; i < responseControls.length; i++) {
										if (responseControls[i] instanceof LDAPPagedResultsResponse) {
											LDAPPagedResultsResponse response = (LDAPPagedResultsResponse) responseControls[i];
											pageResult.setCookie(response
													.getCookie());
										}
									}
								}
							}
						} while (pageResult != null
								&& pageResult.getCookie() != null && count > 0);
						lc.getSearchConstraints().setControls(
								new LDAPControl[0]);
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

		Set<String> accounts = new HashSet<String>();
		try {
			accounts.addAll(getSoffidAccounts(SoffidObjectType.OBJECT_ACCOUNT));
		} catch (Exception e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
		return new LinkedList<String>(accounts);
	}

	
	LDAPSchema schema = null;
	String[] binaySchemas = new String[] {
			"1.3.6.1.4.1.1466.115.121.1.10",
			"1.3.6.1.4.1.1466.115.121.1.23",
			"1.3.6.1.4.1.1466.115.121.1.28",
			"1.3.6.1.4.1.1466.115.121.1.5",
			"1.3.6.1.4.1.1466.115.121.1.8",
			"1.3.6.1.4.1.1466.115.121.1.9"
	};
	protected boolean isBinary(LDAPConnection conn, String attributeName) throws LDAPException {
		if (schema == null) {
			try {
				String c = conn.getSchemaDN();
				if (c == null)
					return false;
				schema = conn.fetchSchema(c);
			} catch (Exception e) {
				return false;
			}
		}
		if (schema == null)
			return false;
		LDAPAttributeSchema p = schema.getAttributeSchema(attributeName);
		if (p == null)
			return false;

		String syntax = p.getSyntaxString();
		if (syntax == null)
			return false;
		final int pos = Arrays.binarySearch(binaySchemas, syntax);
		return pos >= 0;
	}
	
	public ExtensibleObject parseEntry(LDAPConnection conn, LDAPEntry entry, ObjectMapping mapping) throws LDAPException {
		ExtensibleObject eo = new ExtensibleObject();
		eo.setAttribute("dn", entry.getDN());
		eo.setObjectType(mapping.getSystemObject());
		for (Object obj : entry.getAttributeSet()) {
			LDAPAttribute att = (LDAPAttribute) obj;
			if (isBinary(conn, att.getBaseName())) {
				eo.setAttribute(att.getBaseName(), att.getByteValueArray());				
			}
			else if (att.getStringValueArray().length == 1)
				eo.setAttribute(att.getBaseName(), att.getStringValue());
			else
				eo.setAttribute(att.getBaseName(), att.getStringValueArray());
		}
		return eo;
	}

	public Usuari getUserInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		try {
			ExtensibleObject eo = findExtensibleUser(userAccount);
			if (eo == null)
				return null;
			ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
			for (ExtensibleObject peo : parsed.getObjects()) {
				Usuari usuari = vom.parseUsuari(peo);
				if (usuari != null)
					return usuari;
				Account account = vom.parseAccount(peo);
				if (account != null) {
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

	private ExtensibleObject findExtensibleUser(String userAccount)
			throws Exception {
		if (debugEnabled)
			log.info("Searching for account "+userAccount);
		Account acc = getServer().getAccountInfo(userAccount, getCodi());
		Usuari user = null;
		ExtensibleObject account;
		// Generate a dummy object to perform query
		if (acc == null)
		{
			acc = new Account();
			acc.setName(userAccount);
			acc.setDispatcher(getCodi());
			acc.setDisabled(false);
		}
		else
		{
			try {
				user = getServer().getUserInfo(userAccount, getCodi());
			} catch (UnknownUserException e) {
				
			}
		}
		account = user == null ? new UserExtensibleObject(acc, user, getServer()) :  new AccountExtensibleObject(acc, getServer());
		account.setObjectType(SoffidObjectType.OBJECT_ACCOUNT.getValue());
		ExtensibleObject found = findUserByExample(account);
		if (found != null)
			return found;
		account.setObjectType(SoffidObjectType.OBJECT_USER.getValue());
		return findUserByExample(account);
	}

	private ExtensibleObject findUserByExample(ExtensibleObject example)
			throws Exception {
		// For each suitable mappping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().toString()
					.equals(example.getObjectType())) {
				// Generate system objects from source user
				ExtensibleObject systemObject = objectTranslator
						.generateObject(example, objectMapping, true);

				// Search object by dn
				LDAPEntry entry = buscarUsuario(systemObject);
				if (entry != null) {
					LDAPConnection conn = pool.getConnection();
					try {
						return parseEntry(conn, entry, objectMapping);
					} finally {
						pool.returnConnection();
					}
				}
			}
		}
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		Set<String> roles = new HashSet<String>();
		try {
			if (debugEnabled)
				log.info("Getting roles list");
			for (ExtensibleObject eo : getLdapObjects(
					SoffidObjectType.OBJECT_ROLE, null, null, 0)) {
				ExtensibleObjects parsed = objectTranslator
						.parseInputObjects(eo);
				for (ExtensibleObject parsedObject : parsed.getObjects()) {
					if (debugEnabled)
						log.info("Read entry");
					Rol rol = vom.parseRol(parsedObject);
					if (rol != null) {
						if (debugEnabled)
							log.info("Read role "+rol.getNom());
						roles.add(rol.getNom());
					}
				}

			}
		} catch (LDAPException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
		return new LinkedList<String>(roles);
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		try {
			if (debugEnabled)
				log.info("Getting role info for "+roleName);
			ExtensibleObject rolObject = new ExtensibleObject();
			rolObject.setObjectType(SoffidObjectType.OBJECT_ROLE.getValue());
			rolObject.setAttribute("name", roleName);
			rolObject.setAttribute("system", getDispatcher().getCodi());

			// Generate a dummy object to perform query
			ExtensibleObjects systemObjects = objectTranslator
					.generateObjects(rolObject);
			for (ExtensibleObject systemObject : systemObjects.getObjects()) {
				LDAPEntry entry = buscarUsuario(systemObject);
				if (entry != null) {
					if (debugEnabled)
						debugEntry("Got object", entry.getDN(), entry.getAttributeSet());
					for (ExtensibleObjectMapping objectMapping : objectMappings) {
						if (objectMapping.getSoffidObject().toString().equals(
								rolObject.getObjectType().toString())) {
							LDAPConnection conn = pool.getConnection();
							try {
								ExtensibleObject eo = parseEntry(conn, entry,
										objectMapping);
								if (debugEnabled)
									debugObject("Translated to native object", eo, "");
								ExtensibleObject parsed = objectTranslator
										.parseInputObject(eo, objectMapping);
								if (parsed != null) {
									if (debugEnabled)
										debugObject("Translated to Soffid object", parsed, "");
									Rol rol = vom.parseRol(parsed);
									if (rol != null) {
										if (debugEnabled)
											log.info(rol.toString());
										return rol;
									}
								}
							} finally {
								pool.returnConnection();
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

	private boolean populateRolesFromUser(String userAccount, List<Rol> roles)
			throws Exception {
		boolean found = false;
		ExtensibleObject userObject = findExtensibleUser(userAccount);
		if (userObject != null) {
			ExtensibleObjects soffidObjects = objectTranslator
					.parseInputObjects(userObject);
			for (ExtensibleObject soffidObject : soffidObjects.getObjects()) {
				List<Map<String, Object>> grantedRoles = (List<Map<String, Object>>) soffidObject
						.get("grantedRoles");
				if (grantedRoles != null) {
					if (debugEnabled || isDebug())
						log.info("Getting roles from user attribute 'grantedRoles'");
					for (Map<String, Object> grantedRole : grantedRoles) {
						Rol rol = new Rol();
						rol.setBaseDeDades(getDispatcher().getCodi());
						rol.setNom(vom.toSingleString(grantedRole
								.get("grantedRole")));
						rol.setDescripcio(rol.getNom() + " Auto generated");
						roles.add(rol);
					}
					found = true;
				}
				List<String> granted = (List<String>) soffidObject
						.get("granted");
				if (granted != null) {
					if (debugEnabled || isDebug())
						log.info("Getting roles from user attribute 'granted'");
					for (String grantedRole : granted) {
						Rol rol = new Rol();
						rol.setBaseDeDades(getDispatcher().getCodi());
						rol.setNom(grantedRole);
						rol.setDescripcio(rol.getNom() + " Auto generated");
						roles.add(rol);
					}
					found = true;
				}

			}
		}

		return found;
	}

	private boolean populateRolesFromRol(String userAccount, List<Rol> roles)
			throws Exception {
		LDAPConnection conn = pool.getConnection();
		try {
			boolean found = false;
			ExtensibleObject rolObject = new ExtensibleObject();
			rolObject.setObjectType(SoffidObjectType.OBJECT_ROLE.getValue());
			// /
			Map<String, Object> userMap = new HashMap<String, Object>();
			userMap.put("accountName", userAccount);
			userMap.put("system", getDispatcher().getCodi());
			List<Map<String, Object>> userMapList = new LinkedList<Map<String, Object>>();
			userMapList.add(userMap);
			rolObject.setAttribute("allGrantedAccounts", userMapList);
			rolObject.setAttribute("grantedAccounts", userMapList);
			List<String> accountNames = new LinkedList<String>();
			accountNames.add(userAccount);
			rolObject.setAttribute("allGrantedAccountNames", accountNames);
			rolObject.setAttribute("grantedAccountNames", accountNames);

			if (debugEnabled || isDebug())
				debugObject("Searching grants from role object", rolObject, "");
			// Generate a dummy object to perform query
			for (ExtensibleObjectMapping objectMapping : objectMappings) {
				if (objectMapping.getSoffidObject().equals(
						SoffidObjectType.OBJECT_ROLE)) {
					ExtensibleObject systemObject = objectTranslator.generateObject(rolObject, objectMapping);
					StringBuffer sb = new StringBuffer();
	
					if (debugEnabled || isDebug())
						debugObject("Searching grants from LDAP object", systemObject, "");
					boolean any = buildQuery(systemObject, sb);
					if (any && baseDN != null) {
						if (debugEnabled)
							log.info("Performing query " + sb.toString());
						String keyAttribute=objectMapping.getProperties().get("key");
						String[] atts = keyAttribute == null ? null: new String[] {keyAttribute};
						LDAPSearchResults search = conn.search(baseDN,
								LDAPConnection.SCOPE_SUB, sb.toString(),
								atts,
								false);
						if (debugEnabled || isDebug())
							log.info("Executing query "+sb.toString());
						while (search.hasMore()) {
							try {
								LDAPEntry roleEntry = search.next();
								if (debugEnabled || isDebug())
									debugEntry("Got ", roleEntry.getDN(), roleEntry.getAttributeSet());
								
								if ( keyAttribute == null) {
									ExtensibleObject roleObject = parseEntry(
											conn, roleEntry, objectMapping);
									ExtensibleObject soffidObject = objectTranslator
											.parseInputObject(roleObject,
													objectMapping);
									Rol rol = vom.parseRol(soffidObject);
									if (debugEnabled || isDebug())
										log.info("Generated role "+rol);
									if (rol != null) {
										roles.add(rol);
									}
								} else {
									ExtensibleObject roleObject = parseEntry(conn, roleEntry, objectMapping);
									String name = (String) objectTranslator.parseInputAttribute("name", roleObject, objectMapping);
									if (debugEnabled || isDebug()) {
										debugObject("Got ", roleObject, "");
										log.info("Parsed name = "+name);
									}
									if (name != null) {
										Rol rol = new Rol();
										rol.setNom(name);
										rol.setBaseDeDades(getCodi());
										roles.add(rol);
									} else {
										debugObject("Cannot parse name from object", roleObject, "");
									}
								}
								found = true;
							} catch (LDAPException e) {
								if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
									break;
								else
									throw e;
							}
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
		UserExtensibleObject sourceObject = new UserExtensibleObject(account, userData,
				getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		try {
			updateObjects(userName, objects, sourceObject);
			if (smartGrant)
				updateGrants(objects, getServer().getAccountRoles(userName, getDispatcher().getCodi()));
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		Account account = getServer().getAccountInfo(accountName, getCodi());
		if (account == null) {
			account = new Account();
			account.setName(accountName);
			account.setDescription(description);
			account.setDisabled(true);
			account.setDispatcher(getDispatcher().getCodi());			
		}
		AccountExtensibleObject sourceObject = new AccountExtensibleObject(account,
				getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		try {
			updateObjects(accountName, objects, sourceObject);
			if (smartGrant)
				updateGrants(objects, getServer().getAccountRoles(accountName, getDispatcher().getCodi()));
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	private void updateGrants(ExtensibleObjects objects, Collection<RolGrant> accountRoles) throws InternalErrorException {
		for (ExtensibleObjectMapping m: findGroupType("groupOfNames")) {
			updateGrants(objects, accountRoles, m, "groupOfNames", "member", "dn");
		}
		for (ExtensibleObjectMapping m: findGroupType("groupOfUniqueNames")) {
			updateGrants(objects, accountRoles, m, "groupOfUniqueNames", "uniqueMember", "dn");
		}
		for (ExtensibleObjectMapping m: findGroupType("posixGroup")) {
			updateGrants(objects, accountRoles, m, "posixGroup", "memberUid", "uid");
		}
	}

	private void updateGrants(ExtensibleObjects objects, Collection<RolGrant> accountRoles, ExtensibleObjectMapping m,
			String groupType, String groupAttribute, String userAttribute) throws InternalErrorException {
		if (debugEnabled)
			log.info("Smart update of grants on "+m.getSystemObject()+" ("+ accountRoles.size()+")");
		// Compute list of grants to add
		HashMap<String,Rol> memberships = new HashMap<>();
		HashSet<String> groups = new HashSet<>();
		for (RolGrant grant: accountRoles) {
			try {
				Rol r = getServer().getRoleInfo(grant.getRolName(), getDispatcher().getCodi());
				Object dn = objectTranslator.generateAttribute("dn", new RoleExtensibleObject(r, getServer()), m);
				if (dn != null) {
					String d = dn.toString().toLowerCase();
					groups.add(d);
					memberships.put(d, r);
				}
			} catch (UnknownRoleException e) {
			}
		}
		for (ExtensibleObject obj: objects.getObjects()) {
			Object value = obj.get(userAttribute);
			if (value != null) {
				HashSet<String> groups2 = new HashSet<>(groups);
				// Fetch currently assigned grants
				try {
					LDAPConnection conn = pool.getConnection();
					try
					{
						removeGroups(conn, groupType, groupAttribute, userAttribute, value, groups, groups2);

						for (String groupDN: groups2) {
							if (debugEnabled)
								log.info("Adding to group "+groupDN);
							addGroup(conn, groupDN, groupAttribute, value, memberships.get(groupDN));
						}
					} finally {
						pool.returnConnection();
					}
					
				} catch (Exception e1) {
					throw new InternalErrorException ("Error performing LDAP query", e1);
				}
			}
		}
	}

	private void addGroup(LDAPConnection conn, String groupDN, String groupAttribute, Object value, Rol rol) throws InternalErrorException, LDAPException, RemoteException {
		LDAPEntry entry = null;
		try {
			entry = conn.read(groupDN, new String[] {"cn"});
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.NO_SUCH_OBJECT)
				throw e;
		}
		if (entry == null) {
			updateRole(rol);
			try {
				entry = conn.read(groupDN, new String[] {groupAttribute});
			} catch (LDAPException e) {
				if (e.getResultCode() != LDAPException.NO_SUCH_OBJECT) return; 
			}
		}
		if (debugEnabled) {
			log.info("Adding member "+value.toString()+" to "+groupDN);
		}
		LDAPModification m;
		m = new LDAPModification(LDAPModification.ADD, new LDAPAttribute(groupAttribute, value.toString()));
		conn.modify(entry.getDN(), m);
	}

	protected void removeGroups(LDAPConnection conn, String groupType, String groupAttribute, String userAttribute, Object value,
			HashSet<String> groups, HashSet groups2) throws LDAPException {
		String queryString = "(&("+groupAttribute+"="+escapeLDAPSearchFilter(value.toString())+")"
				+ "(objectClass="+groupType+"))";
		LDAPPagedResultsControl pageResult = null;
		if (pagesize > 0) {
			pageResult  = new LDAPPagedResultsControl(pagesize, false);
		}

		if (debugEnabled)
			log.info("Searching query "+queryString+" on "+baseDN);
		do {
			LDAPSearchConstraints constraints = conn.getSearchConstraints();
			if (pageResult != null) {
				constraints.setControls(pageResult);
			}
			constraints.setMaxResults(0);

			LDAPSearchResults query = conn.search(baseDN,
					LDAPConnection.SCOPE_SUB, queryString, new String[] {"CN"}, false,
							constraints);
			while (query.hasMore()) {
				try {
					LDAPEntry entry = query.next();
					if (debugEnabled)
						log.info("Got "+entry.getDN());
					if (! groups.contains(entry.getDN().toLowerCase()))
						removeEntry(conn, entry, groupAttribute, value.toString());
					else
						groups2.remove(entry.getDN().toLowerCase());
				} 
				catch (LDAPReferralException e)
				{
				}
			}			
			if (pageResult != null) {
				LDAPControl responseControls[] = query.getResponseControls();
				pageResult.setCookie(null); 
				if (responseControls != null) {
					for (int i = 0; i < responseControls.length; i++) {
						if (responseControls[i] instanceof LDAPPagedResultsResponse) {
							LDAPPagedResultsResponse response = (LDAPPagedResultsResponse) responseControls[i];
							pageResult.setCookie(response.getCookie());
						}
					}
				}
			}
		} while (pageResult != null 
				&& pageResult.getCookie() != null 
				&& pagesize > 0);
	}

	private void removeEntry(LDAPConnection conn, LDAPEntry entry, String groupAttribute, String value) throws LDAPException {
		if (debugEnabled) {
			log.info("Removing member "+value.toString()+" from "+entry);
		}
		LDAPModification m = new LDAPModification(LDAPModification.DELETE, new LDAPAttribute(groupAttribute, value));
		try {
			conn.modify(entry.getDN(), m);
		} catch (LDAPException e) {
			entry = conn.read(entry.getDN());
			if (e.getResultCode() == LDAPException.OBJECT_CLASS_VIOLATION &&
					oneElement(entry.getAttribute(groupAttribute))) // One single element
			{
				m = new LDAPModification(LDAPModification.REPLACE, new LDAPAttribute(groupAttribute, 
								groupAttribute.equalsIgnoreCase("memberUid") ? "-1": "cn=nobody,"+baseDN));
				conn.modify(entry.getDN(), m);
			}
			else
				throw e;
		}
	}

	private boolean oneElement(LDAPAttribute attribute) {
		Enumeration enumeration = attribute.getStringValues();
		if (!enumeration.hasMoreElements())
			return true;
		enumeration.nextElement();
		if (!enumeration.hasMoreElements())
			return true;
		else
			return false;
	}

	private List<ExtensibleObjectMapping> findGroupType(String desiredType) throws InternalErrorException {
		List<ExtensibleObjectMapping> r = new LinkedList<>();
		nextMapping: for (ExtensibleObjectMapping m: objectTranslator.getObjects()) {
			if (m.getSoffidObject().toString().equals(SoffidObjectType.OBJECT_ROLE.toString())) {
				ExtensibleObject o = new ExtensibleObject();
				o.setObjectType(SoffidObjectType.OBJECT_ROLE.toString());
				Object type = objectTranslator.generateAttribute("objectClass", o, m);
				if (type != null && type.toString().toLowerCase().contains(desiredType.toLowerCase())) 
					r .add(m);
			}
		}
		return r;
	}

	public void removeUser(String userName) throws RemoteException,
			InternalErrorException {
		Account account = getServer().getAccountInfo(userName, getCodi());
		ExtensibleObjects objects;
		try {
			if (account == null || removeDisabledUser(account)) {
				account = new Account();
				account.setName(userName);
				account.setDescription(userName);
				account.setDisabled(true);
				account.setDispatcher(getDispatcher().getCodi());
				AccountExtensibleObject sourceObject = new AccountExtensibleObject(account,
						getServer());
				objects = objectTranslator
						.generateObjects(sourceObject);
				removeObjects(objects, sourceObject);
				if (smartGrant)
					updateGrants(objects, new LinkedList<>());
			} else {
				AccountExtensibleObject sourceObject = new AccountExtensibleObject(account,
						getServer());
				try {
					Usuari user = getServer().getUserInfo(userName,
							getDispatcher().getCodi());
					UserExtensibleObject sourceObject2 = new UserExtensibleObject(account,
							user, getServer());
					objects = objectTranslator
							.generateObjects(sourceObject2);
					updateObjects(userName, objects, sourceObject2);
				} catch (UnknownUserException e) {
					objects = objectTranslator
							.generateObjects(sourceObject);
					updateObjects(userName, objects, sourceObject);
					if (smartGrant)
						updateGrants(objects, new LinkedList<>());
				}
			}
		} catch (Exception e) {
			throw new InternalErrorException("Error removing user", e);
		}
	}

	private boolean removeDisabledUser(Account account) {
		for (ExtensibleObjectMapping mapping: objectMappings) {
			if (mapping.getSoffidObject() == SoffidObjectType.OBJECT_ACCOUNT && account.getType() != AccountType.USER ||
					mapping.getSoffidObject() == SoffidObjectType.OBJECT_USER && account.getType() == AccountType.USER) {
				if ("true".equals(mapping.getProperties().get("removeDisabledAccounts")))
					return true;
			}
		}
		return false;
	}

	public void updateUserPassword(String userName, Usuari userData,
			Password password, boolean mustchange) throws RemoteException,
			InternalErrorException {
		Account account = getServer().getAccountInfo(userName, getCodi());
		if (account == null)
			return;
		ExtensibleObject sourceObject = userData == null? 
				new AccountExtensibleObject(account, getServer()) :
			new UserExtensibleObject(account, userData,
				getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		try {
			updatePassword(userName, objects, sourceObject, password, mustchange);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public boolean validateUserPassword(String user, Password password)
			throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(user);
		acc.setDescription(user);
		acc.setDispatcher(getDispatcher().getCodi());
		ExtensibleObjects entries;
		try {
			Usuari usuari = getServer().getUserInfo(user,
					getDispatcher().getCodi());
			entries = objectTranslator
					.generateObjects(new UserExtensibleObject(acc, usuari,
							getServer()));
		} catch (UnknownUserException e) {
			entries = objectTranslator
					.generateObjects(new AccountExtensibleObject(acc,
							getServer()));
		}
		for (ExtensibleObject entry : entries.getObjects()) {
			try {
				LDAPEntry ldapEntry = buscarUsuario(entry);
				String dn = ldapEntry == null ? 
						vom.toSingleString(entry.getAttribute("dn")) :
					ldapEntry.getDN();
				if (dn != null) {
					LDAPConnection conn2 = new LDAPConnection();
					conn2.connect(ldapHost, ldapPort);
					if (debugEnabled)
						log.info("Connecting to "+ldapHost+":"+ldapPort+" with DN "+dn);
					conn2.bind(ldapVersion, dn, password.getPassword()
							.getBytes("UTF8"));
					conn2.disconnect();
					return true;
				}
			} catch (Exception e) {
				log.info("Error connecting as user " + user + ":"
						+ e.toString());
			}
		}
		return false;
	}

	public void updateRole(Rol rol) throws RemoteException,
			InternalErrorException {
		if (!getCodi().equals(rol.getBaseDeDades()))
			return;
		RoleExtensibleObject sourceObject = new RoleExtensibleObject(rol, getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);

		try {
			updateObjects(null, objects, sourceObject);
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
		RoleExtensibleObject sourceObject = new RoleExtensibleObject(rol, getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		try {
			removeObjects(objects, sourceObject);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	private String firstChange = null;
	Long currentTime = null;
	
	public Collection<AuthoritativeChange> getChanges(String nextChange)
			throws InternalErrorException {
		Collection<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		try {
			if (currentTime == null)
				currentTime = new Long(System.currentTimeMillis() - 300000L); // 5 minutes clock skew
			LinkedList<ExtensibleObject> objects = getLdapObjects(
					SoffidObjectType.OBJECT_USER, firstChange, nextChange, pagesize);
			if (objects.isEmpty()) {
				firstChange = null;
			}

			for (ExtensibleObject ldapObject : objects) {
				debugObject("LDAP Object", ldapObject, "");
				firstChange = vom.toSingleString(ldapObject.getAttribute("dn"));
				ExtensibleObjects parsedObjects = objectTranslator
						.parseInputObjects(ldapObject);
				for (ExtensibleObject object : parsedObjects.getObjects()) {
					debugObject("Parsed Object", object, "");
					Usuari user = vom.parseUsuari(object);
					if (user != null) {
						if (debugEnabled)
							log.info("Resulting object. " + user.toString());
						AuthoritativeChange change = new AuthoritativeChange();

						AuthoritativeChangeIdentifier id = new AuthoritativeChangeIdentifier();
						change.setId(id);
						id.setChangeId(null);
						id.setEmployeeId(user.getCodi());
						id.setDate(new Date());

						change.setUser(user);

						Object groups = object.getAttribute("secondaryGroups");
						if (groups instanceof Collection) {
							Set<String> groupsList = new HashSet<String>();
							for (Object group : (Collection<Object>) object) {
								if (group instanceof String) {
									groupsList.add((String) group);
								} else if (group instanceof ExtensibleObject) {
									Object name = (String) ((ExtensibleObject) group)
											.getAttribute("name");
									if (name != null)
										groupsList.add(name.toString());
								} else if (group instanceof Group) {
									groupsList.add(((Group) group).getName());
								} else if (group instanceof Grup) {
									groupsList.add(((Grup) group).getCodi());
								}
							}
							change.setGroups(groupsList);
						}

						Object attributes = object.getAttribute("attributes");
						if (attributes instanceof Map) {
							Map<String, Object> attributesMap = new HashMap<String, Object>();
							for (Object attributeName : ((Map) attributes)
									.keySet()) {
								Object obj = ((Map) attributes)
												.get(attributeName);
								if (obj != null) {
									if (obj instanceof Collection &&
											((Collection) obj).size() > 1)
										attributesMap.put((String) attributeName, obj);
									if (obj.getClass().isArray() && 
											Array.getLength(obj) > 1)
										attributesMap.put((String) attributeName, obj);
									else
										attributesMap.put((String) attributeName, vom
											.toSingleton(obj));
								}
							}
							change.setAttributes(attributesMap);
						}

						changes.add(change);

					}
				}

			}
		} catch (LDAPException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
		return changes;
	}

	public void debugModifications(String action, String dn,
			LDAPModification mods[]) {
		if (debugEnabled) {
			log.info("=========================================================");
			log.info(action + " object " + dn);
			for (int i = 0; i < mods.length; i++) {
				LDAPModification mod = mods[i];
				debugAttribute(mod.getOp(), mod.getAttribute());
			}
			log.info("=========================================================");
		}
	}

	private void debugAttribute(int op, LDAPAttribute ldapAttribute) {
		String attAction = op == LDAPModification.ADD ? "ADD"
				: op == LDAPModification.DELETE ? "DELETE" : "REPLACE";
		StringBuffer b = new StringBuffer(attAction);
		b.append(" ").append(ldapAttribute.getName());
		if (op != LDAPModification.DELETE) {
			b.append(" = [");
			String[] v = ldapAttribute.getStringValueArray();
			for (int j = 0; j < v.length; j++) {
				if (j > 0)
					b.append(", ");
				if (v[j] == null)
					b.append("null");
				else if (v[j].length() > 80)
					b.append(v[j].substring(0, 80));
				else
					b.append(v[j]);
			}
			b.append("]");
		}
		log.info(b.toString());
	}

	public boolean hasMoreData() throws InternalErrorException {
		return firstChange != null;
	}

	public String getNextChange() throws InternalErrorException {
		if (currentTime == null)
			return null;
		else {
			final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
			dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
			return dateFormat.format(new Date(currentTime));
		}
	}

	void debugObject(String msg, Map<String, Object> obj, String indent) {
		if (debugEnabled) {
			if (msg != null)
				log.info(indent + msg);
			for (String attribute : obj.keySet()) {
				Object subObj = obj.get(attribute);
				if (subObj == null) {
					log.info(indent + attribute.toString() + ": null");
				} else if (subObj instanceof Map) {
					log.info(indent + attribute.toString() + ": Object {");
					debugObject(null, (Map<String, Object>) subObj, indent
							+ "   ");
					log.info(indent + "}");
				} else {
					log.info(indent + attribute.toString() + ": "
							+ subObj.toString());
				}
			}
		}
	}

	public static String escapeDN(String name) {
		StringBuffer sb = new StringBuffer(); // If using JDK >= 1.5 consider
												// using StringBuilder
		if ((name.length() > 0)
				&& ((name.charAt(0) == ' ') || (name.charAt(0) == '#'))) {
			sb.append('\\'); // add the leading backslash if needed
		}
		for (int i = 0; i < name.length(); i++) {
			char curChar = name.charAt(i);
			switch (curChar) {
			case '\\':
				sb.append("\\\\");
				break;
			case ',':
				sb.append("\\,");
				break;
			case '+':
				sb.append("\\+");
				break;
			case '"':
				sb.append("\\\"");
				break;
			case '<':
				sb.append("\\<");
				break;
			case '>':
				sb.append("\\>");
				break;
			case ';':
				sb.append("\\;");
				break;
			default:
				sb.append(curChar);
			}
		}
		if ((name.length() > 1) && (name.charAt(name.length() - 1) == ' ')) {
			sb.insert(sb.length() - 1, '\\'); // add the trailing backslash if
												// needed
		}
		return sb.toString();
	}

	protected boolean postDelete(ExtensibleObject soffidObject,
			LDAPEntry currentEntry) throws InternalErrorException {
		return true;
	}

	protected boolean postInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean postUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean postPassword(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean preDelete(ExtensibleObject soffiObject,
			LDAPEntry currentEntry) throws InternalErrorException {
		return true;
	}

	protected boolean preInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject) throws InternalErrorException {
		return true;
	}

	protected boolean preUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean prePassword(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return true;
	}

	public void debugEntry(String action, String dn, LDAPAttributeSet atts) {
		if (debugEnabled) {
			log.info("=========================================================");
			log.info(action + " object " + dn);
			for (Iterator iterator = atts.iterator(); iterator.hasNext();) {
				LDAPAttribute att = (LDAPAttribute) iterator.next();
				debugAttribute(-1, att);
			}
			log.info("=========================================================");
		}
	}

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	public Account getAccountInfo(String userAccount) throws RemoteException, InternalErrorException {
		try {
			if (debugEnabled)
				log.info("Fetching account "+userAccount+" from LDAP server");
			ExtensibleObject eo = findExtensibleUser(userAccount);
			if (eo == null) {
				if (debugEnabled)
					log.info("Cannot find account");
				return null;
			} else {
				if (debugEnabled)
					debugObject("Got LDAP object", eo, "   ");
			}
			ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
			for (ExtensibleObject peo : parsed.getObjects()) {
				if (debugEnabled)
					debugObject("Translated to Soffid object", peo, "   ");
				Account usuari = vom.parseAccount(peo);
				if (usuari != null) {
					if (debugEnabled) log.info("Soffid account: "+usuari.toString());
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

	public List<RolGrant> getAccountGrants(String userAccount) throws RemoteException, InternalErrorException {
		List<RolGrant> grants = new LinkedList<RolGrant>();
		LinkedList<Rol> roles;
		try {
			if (debugEnabled)
				log.info("Fetching account "+userAccount+" grants from LDAP server");
			roles = new LinkedList<Rol>();
			if (!populateRolesFromUser(userAccount, roles))
				populateRolesFromRol(userAccount, roles);
			if (debugEnabled)
				log.info("Returning "+roles.size()+" grants");
			for (Rol role : roles)
			{
				RolGrant rg = new RolGrant();
				rg.setRolName(role.getNom());
				rg.setDispatcher(getCodi());
				rg.setInformationSystem(role.getCodiAplicacio());
				rg.setOwnerAccountName(userAccount);
				rg.setOwnerDispatcher(getCodi());
				grants.add(rg);
			}
		} catch (Exception e) {
			throw new InternalErrorException("Error accessing LDAP", e);
		}
		return grants;
	}
	
	public Collection<Map<String, Object>> invoke(String verb, String command,
			Map<String, Object> params) throws RemoteException, InternalErrorException 
	{
		if ("add".equalsIgnoreCase(verb) || "insert".equalsIgnoreCase(verb))
		{
			return addLdapObject (command, params);
		}
		else if ("update".equalsIgnoreCase(verb) || "modify".equalsIgnoreCase(verb))
		{
			return modifyLdapObject (command, params);
		}
		else if ("delete".equalsIgnoreCase(verb) || "remove".equalsIgnoreCase(verb))
		{
			return deleteLdapObject (command, params);
		}
		else if ("select".equalsIgnoreCase(verb) || "query".equalsIgnoreCase(verb))
		{
			return queryLdapObjects (baseDN, command, params);
		}
		else if ("rename".equalsIgnoreCase(verb))
		{
			return renameLdapObjects (command, params);
		}
		else if ("get".equalsIgnoreCase(verb) || "read".equalsIgnoreCase(verb))
		{
			log.info("Getting "+baseDN+" "+command);
			Collection<Map<String, Object>> l = getLdapObjects (baseDN, command, params);
			Collection<Map<String,Object>> l2  = new LinkedList();
			for (Map<String, Object> eo: l)
			{
				Map<String, Object> eo2 = new HashMap<String, Object>();
				for (String key: eo.keySet())
				{
					eo2.put(key, eo.get(key));
				}
				l2.add(eo2);
			}
			return l2;
		}
		else if (verb.equals("checkPassword"))
		{
			Collection<Map<String, Object>> l = new LinkedList<Map<String, Object>>();
			Map<String,Object> o = new HashMap<String, Object>();
			l.add(o);
			Account account = getServer().getAccountInfo(command, getDispatcher().getCodi());
			if (account == null)
				o.put("passwordStatus", null);
			else 
			{
				try {
					Password password = getServer().getAccountPassword(command, getDispatcher().getCodi());
					PasswordValidation status = validateUserPassword(account.getName(), password) ? PasswordValidation.PASSWORD_GOOD: PasswordValidation.PASSWORD_WRONG;
					o.put("passwordStatus", status);
				} catch (InternalErrorException e) {
					throw e;
				} catch (Exception e) {
					throw new InternalErrorException ("Error validating password for account "+account.getLoginName(),
							e);
				}
			}
			return l;
		}

		else
		{
			return queryLdapObjects (verb, command, params);
		}
	}

	private Collection<Map<String, Object>> queryLdapObjects(String base, String queryString, Map<String, Object> params) throws InternalErrorException {
		if (params.get("base") != null)
			base = (String) params.get("base");
		try {
			LDAPConnection conn = pool.getConnection();
			try
			{
				LinkedList<Map<String, Object>> result = new LinkedList<Map<String,Object>>();
				
				LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
				LDAPSearchResults query = conn.search(base,
							LDAPConnection.SCOPE_SUB, queryString, null, false,
							constraints);
				while (query.hasMore()) {
					try {
						LDAPEntry entry = query.next();
						result.add( buildExtensibleObject(entry) );
					} 
					catch (LDAPReferralException e)
					{
						// Ignore
					}
				}			
				return result;
			} finally {
				pool.returnConnection();
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error performing LDAP query", e1);
		}
	}
	
	private Collection<Map<String, Object>> renameLdapObjects(String olddn, Map<String, Object> params) throws InternalErrorException {
		String newdn = (String) params.get("dn");
		
		try {
			LDAPConnection conn = pool.getConnection();
			try
			{
				LinkedList<Map<String, Object>> result = new LinkedList<Map<String,Object>>();
				
				try {
					LDAPEntry entry = conn.read(olddn);
					if (entry != null) {
						String[] split = splitDN(newdn);
						String parentName =  mergeDN(split, 1);
						conn.rename(entry.getDN(), split[0], parentName, true);
					}
				} 
				catch (LDAPReferralException e)
				{
					// Ignore
				}
				catch (LDAPException e2)
				{
					if (e2.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
						// Ignore
					} else {
						log.debug("LDAP Exception: "+e2.toString());
						log.debug("ERROR MESSAGE: "+e2.getLDAPErrorMessage());
						log.debug("LOCALIZED MESSAGE: "+e2.getLocalizedMessage());
						throw e2;
					}
				}
				return result;
			} finally {
				pool.returnConnection();
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error performing LDAP query", e1);
		}
	}

	private Collection<Map<String, Object>> getLdapObjects(String base, String queryString, Map<String, Object> params) throws InternalErrorException {
		try {
			LDAPConnection conn = pool.getConnection();
			try
			{
				LinkedList<Map<String, Object>> result = new LinkedList<Map<String,Object>>();
				
				try {
					LDAPEntry entry = conn.read(queryString);
					result.add( buildExtensibleObject(entry) );
				} 
				catch (LDAPReferralException e)
				{
					// Ignore
				}
				catch (LDAPException e2)
				{
					if (e2.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
						// Ignore
					} else {
						log.debug("LDAP Exception: "+e2.toString());
						log.debug("ERROR MESSAGE: "+e2.getLDAPErrorMessage());
						log.debug("LOCALIZED MESSAGE: "+e2.getLocalizedMessage());
						throw e2;
					}
				}
				return result;
			} finally {
				pool.returnConnection();
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error performing LDAP query", e1);
		}
	}
	
	private Collection<Map<String, Object>> deleteLdapObject(String dn, Map<String, Object> params) throws InternalErrorException {
		try {
			LDAPConnection conn = pool.getConnection();
			try
			{
				conn.delete(dn);
				return null;
			} finally {
				pool.returnConnection();
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error performing LDAP query", e1);
		}
	}
	
	private Collection<Map<String, Object>> modifyLdapObject(String dn, Map<String, Object> params) throws InternalErrorException {
		try {
			LDAPConnection conn = pool.getConnection();
			try
			{
				LDAPEntry entry = conn.read(dn);
				List<LDAPModification> mods = new LinkedList<LDAPModification>();
				for (String param: params.keySet())
				{
					if (!param.equals("dn"))
					{
						Object value = params.get(param);
						LDAPAttribute previous = entry.getAttribute(param);
						if (value == null
								&& previous != null) {
							mods.add(new LDAPModification(
									LDAPModification.DELETE,
									new LDAPAttribute(param)));
						} else if (value != null
								&& previous == null) {
							if (value instanceof byte[]) {
								mods.add(new LDAPModification(
										LDAPModification.ADD,
										new LDAPAttribute(param,
												(byte[]) value)));
							} else  if (value instanceof String[]) {
								mods.add(new LDAPModification(
										LDAPModification.ADD,
										new LDAPAttribute(param, (String[])value)));
							} else {
								mods.add(new LDAPModification(
										LDAPModification.ADD,
										new LDAPAttribute(param, value.toString())));
							}
						} else if ((value != null)
								&& (previous != null)) {
							if (value instanceof byte[]) {
								mods.add(new LDAPModification(
										LDAPModification.REPLACE,
										new LDAPAttribute(param,
												(byte[]) value)));
							} else  if (value instanceof String[]) {
								mods.add(new LDAPModification(
										LDAPModification.REPLACE,
										new LDAPAttribute(param, (String[])value)));
							} else {
								mods.add(new LDAPModification(
										LDAPModification.REPLACE,
										new LDAPAttribute(param, value.toString())));
							}
						}
					}
				}
				if (debugEnabled)
					debugModifications("Modifying object ",
						dn,
						mods.toArray(new LDAPModification[0]));
				conn.modify(dn, mods.toArray(new LDAPModification[0]));
				return null;
			} finally {
				pool.returnConnection();
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error modifying LDAP query", e1);
		}
	}
	
	protected Collection<Map<String, Object>> addLdapObject(String dn, Map<String, Object> params) throws InternalErrorException {
		try {
			LDAPConnection conn = pool.getConnection();
			try
			{
				LDAPAttributeSet attributes = new LDAPAttributeSet();
				for (String param: params.keySet())
				{
					Object value = params.get(param);
					if (value == null)
					{
						// Nothing to do
					}
					else if (value instanceof byte[]) 
					{
						attributes.add(
								new LDAPAttribute(param,
										(byte[]) value));
					} else  if (value instanceof String[]) {
						attributes.add(new LDAPAttribute(param, (String[])value));
					} else {
						attributes.add(new LDAPAttribute(param, value.toString()));
					}
				}
				if (debugEnabled)
					debugEntry("Creating object", dn, attributes);
				conn.add( new LDAPEntry(dn, attributes));
				return null;
			} finally {
				pool.returnConnection();
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error modifying LDAP query", e1);
		}
		
	}


	protected ExtensibleObject buildExtensibleObject(LDAPEntry currentEntry) {
		ExtensibleObject old = new ExtensibleObject();
		
		for ( Iterator<LDAPAttribute> it = currentEntry.getAttributeSet().iterator(); it.hasNext(); ) {
			LDAPAttribute att = it.next();
			String [] v = att.getStringValueArray();
			if (v.length == 1)
				old.setAttribute(att.getName(), v[0]);
			else
				old.setAttribute(att.getName(), v);
		}
		old.setAttribute("dn", currentEntry.getDN());
		return old;
	}
	
	private String[] splitDN (String dn)
	{
		List <String> s = new LinkedList<String>();
		int start = 0;
		int i = 1;
		do
		{
			i = dn.indexOf(",", i);
			if (i < 0)
			{
				s.add(dn.substring(start));
				break;
			}
			if (i > 0 && dn.charAt(i-1) != '\\')
			{
				s.add( dn.substring(start, i));
				start = i+1;
			}
			i ++;
		} while (true);
		return s.toArray(new String[s.size()]);
	}
	
	private String mergeDN(String[] parts, int position) {
		String dn = "";
		for (int i = position; i < parts.length; i++)
		{
			if ( i > position ) dn += ",";
			dn += parts[i];
		}
		return dn;
	}

	public ExtensibleObject find(ExtensibleObject pattern) throws Exception {
		LDAPEntry entry = buscarUsuario(pattern);
		if (entry == null)
			return null;
		return buildExtensibleObject(entry);
	}

	public void updateUserAlias(String useKey, Usuari user) throws InternalErrorException {
	}

	public void removeUserAlias(String userKey) throws InternalErrorException {
	}

	public void updateListAlias(LlistaCorreu llista) throws InternalErrorException {
		MailListExtensibleObject sourceObject = new MailListExtensibleObject(llista, getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		try {
			updateObjects(null, objects, sourceObject);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public void removeListAlias(String nomLlista, String domini) throws InternalErrorException {
		LlistaCorreu llista  =new LlistaCorreu();
		llista.setNom(nomLlista);
		llista.setCodiDomini(domini);
		MailListExtensibleObject sourceObject = new MailListExtensibleObject(llista, getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		try {
			removeObjects(objects, sourceObject);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public void updateGroup(Group grup) throws RemoteException, InternalErrorException {
		GroupExtensibleObject sourceObject = new GroupExtensibleObject(Grup.toGrup(grup), getCodi(), getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);

		try {
			updateObjects(null, objects, sourceObject);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	public void removeGroup(String key) throws RemoteException, InternalErrorException {
		Grup grup = new Grup();
		grup.setCodi(key);
		GroupExtensibleObject sourceObject = new GroupExtensibleObject(grup, getCodi(), getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		try {
			removeObjects(objects, sourceObject);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Unexpected exception", e);
		}
	}

	  public void updateExtensibleObject (ExtensibleObject obj) throws RemoteException, InternalErrorException {
		  //Nothing
	  }

	  public void removeExtensibleObject (ExtensibleObject obj) throws RemoteException, InternalErrorException {
		  //Nothing
	  }

	  public List<HostService> getHostServices() throws RemoteException, InternalErrorException {
		  // Nothing
		  return null;
	  }
}
