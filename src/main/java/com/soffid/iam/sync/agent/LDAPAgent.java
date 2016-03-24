package com.soffid.iam.sync.agent;

import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Vector;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchResults;

import es.caib.seycon.ng.comu.*;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.intf.GroupMgr;
import es.caib.seycon.ng.sync.intf.MailAliasMgr;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

/**
 * Agente que gestiona los usuarios y contraseñas del LDAP Hace uso de las
 * librerias jldap de Novell
 * <P>
 * 
 * @author $Author: u88683 $
 * @version $Revision: 1.5 $
 */

public class LDAPAgent extends Agent implements UserMgr, RoleMgr, GroupMgr {

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
	/** Rama base del arbol */
	String containerName;
	/** Use memberof attribute */
	boolean useMemberOf = false;
	/** ofuscador de claves SHA */
	static MessageDigest digest;
	String usersContext;
	String rolesContext;

	// Vamos a er la hora en la que empieza y la hora en la que acaba.
	long inicio;
	long fin;
	int usuarios = 0;
	// --------------------------------------------------------------
	static Hashtable pool = new Hashtable();

	/**
	 * Constructor
	 * 
	 * @param params
	 *            Parámetros de configuración:
	 *            <li>0 = código de usuario LDAP </li>
	 *            <li>1 = contraseña de acceso LDAP </li>
	 *            <li>2 = host</li>
	 *            <li>3 = Rama base del arbol </li>
	 *            <li>4 = bds cuyos roles se tienen que propagar [separados por espacio]</li>
	 */
	public LDAPAgent() throws RemoteException {
	}
	
	@Override
	public void init()
	{
//		super(params);
		log.info("Starting LDAPAgente agent on {}", getDispatcher().getCodi(), null);
		loginDN = getDispatcher().getParam0();
		password = Password.decode(getDispatcher().getParam1()).getPassword();
		// password = params[1];
		ldapHost = getDispatcher().getParam2();
		containerName = getDispatcher().getParam3();
		useMemberOf = "Y".equals(getDispatcher().getParam4());
		usersContext = getDispatcher().getParam5();
		if (usersContext == null || usersContext.trim().length() == 0)
			usersContext = containerName;
		rolesContext = getDispatcher().getParam6();
		if (rolesContext == null || rolesContext.trim().length() == 0)
			rolesContext = containerName;
		
	}

	/**
	 * Actualiza los datos del usuario de la clase inetOrgPerson Inserta si
	 * es necesario una entrada de la clase inetOrgPerson en el directorio
	 * LDAP.<BR>
	 * Si el usuario no está activo elimina la entrada del directorio LDAP
	 * @throws es.caib.seycon.ng.exception.InternalErrorException 
	 */
	public void updateUser(String account, Usuari usuario) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		LDAPEntry ldapuser;
		Collection<RolGrant> userRoles;
		
		try {
			ldapuser = buscarUsuario(account); //lo buscamos (ui puede ser nulo)
			userRoles = getServer().getAccountRoles(account, getDispatcher().getCodi());
			
			if (ldapuser != null) {
				modificarUsuario(ldapuser, account, usuario, userRoles);
			} else {
				addUsuario(account, usuario, userRoles);
			}
		} catch (Exception e) {
			String msg = String.format("UpdateUser('%s'): Error en la propagación de usuarios a LDAP. [%s]",
					account, e.getMessage());
			log.warn(msg, e);
			throw new es.caib.seycon.ng.exception.InternalErrorException(msg,e);
		} 
	}

	public boolean ValidateUserPassword(String user, Password password)
			throws RemoteException, InternalErrorException {
		return false;
	}

	/**
	 * Actualiza la contraseña del usuario. Genera la ofuscación SHA-1 y la
	 * asigna al atributo userpassword de la clase inetOrgPerson
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void updateUserPassword(String user, Usuari usuario,
			es.caib.seycon.ng.comu.Password password, boolean mustchange)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		LDAPAttribute atributo;
		LDAPEntry ldapUser;
		
		try {
			ldapUser = buscarUsuario(user); //ui puede ser nulo
			
			if (ldapUser == null) {
				// Generem un error perquè potser que l'usuari encara
				// no esté donat d'alta al ldap [usuaris alumnes]: u88683 27/01/2011
				log.info("UpdateUserPassword - usuari {} no trobat al ldap, però és actiu - cridem UpdateUser", user, null);
				updateUser(user, usuario);
				ldapUser = buscarUsuario(user); 
			}
						
			ArrayList modList = new ArrayList();
			if (ldapUser != null) {
				String dn = ldapUser.getDN();
				String hash = getHashPassword(password);
				atributo = new LDAPAttribute("userPassword", hash);
				modList.add(new LDAPModification(LDAPModification.REPLACE,
						atributo));
				LDAPModification[] mods = new LDAPModification[modList.size()];
				mods = new LDAPModification[modList.size()];
				mods = (LDAPModification[]) modList.toArray(mods);
				getConnection().modify(dn, mods);
				log.info("UpdateUserPassword - setting password for user {}", user, null);
			}
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.UNWILLING_TO_PERFORM) {
				// se intenta crear el usuario y luego se vuelve a llamar a la
				// función de actualizar el password
				try {
					updateUser(user, usuario);
					updateUserPassword(user, usuario, password, mustchange);
				} catch (Exception ex) {
					String msg = "UpdateUserPassword('" + user+ "'). ["+ex.getMessage()+"]";
					log.warn(msg,ex);
					throw new InternalErrorException(msg,ex);
				}
			} else {
				String msg = "UpdateUserPassword('" + user+ "')";
				log.warn (msg,e);
				throw new InternalErrorException(msg + e.getMessage(),e);
			}
		} catch (InternalErrorException e) {
			String msg = "Error UpdateUserPassword('" + user + "'). ["+e.getMessage()+"]";
			log.warn(msg,e);
			throw e;
		} catch (RemoteException e) {
			String msg = "Error UpdateUserPassword('" + user + "'). ["+e.getMessage()+"]";
			log.warn(msg,e);
			throw e;
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
		LDAPConnection conn = (LDAPConnection) pool.get(getDispatcher().getCodi());
		if (conn != null && ! conn.isConnectionAlive())
		{
			cerrarConexion();
			conn = null;
		}
		if (conn == null) { //Verifiquem que siga activa
			try {
				conn = new LDAPConnection();
				conn.connect(ldapHost, ldapPort);
				conn.bind(ldapVersion, loginDN, password.getBytes("UTF8"));
				pool.put(getDispatcher().getCodi(), conn);
			} catch (Exception e) {
				String msg = "getConnection(): Error en la conexión con LDAP. ["+ e.getMessage()+"]";
				log.warn(msg,e);
				throw new InternalErrorException(msg,e);
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
		LDAPConnection conn = (LDAPConnection) pool.get(getDispatcher().getCodi());
		if (conn != null) {
			pool.remove(getDispatcher().getCodi());
			try {
				conn.disconnect();
			} catch (LDAPException e) {

			}
		}
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
	private LDAPEntry buscarUsuario(String user) throws InternalErrorException {
		try {
			LDAPEntry Entry = new LDAPEntry();
			String searchBase = usersContext;
			String searchFilter = "(&(objectClass=inetOrgPerson)(cn="
					+ user + "))";
			int searchScope = LDAPConnection.SCOPE_ONE;
			LDAPSearchResults searchResults = getConnection().search(searchBase,
					searchScope, searchFilter, null, // return all attributes
					false); // return attrs and values
			if (searchResults.hasMore()) {
				Entry = searchResults.next();
			} else {
				Entry = null;
			}
			return (Entry);
		} catch (Exception e) {
			String msg = "buscarUsuario ('" + user + "'). Error al buscar el usuario. ["+ e.getMessage()+"]";
			log.warn(msg, e);
			throw new InternalErrorException(msg,e);
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
			hash = "{SHA}" + toBase64(digest.digest(password.getPassword().getBytes()));
		}
		return hash;
	}

	/**
	 * Añade los datos de un usuario al directorio LDAP
	 * 
	 * @param usuario
	 *            Informacion del usuario
	 * @throws InternalErrorException
	 *             Error al añadir el usuario al directorio LDAP
	 */
	private void addUsuario(String account, Usuari usuario, Collection<RolGrant> userRoles)
			throws InternalErrorException {
		try {
			log.info ("Creating user {}", account, null);
			LDAPAttributeSet attributeSet = new LDAPAttributeSet();
			attributeSet.add(new LDAPAttribute("objectclass", new String[] {
					"inetOrgPerson" }));
			attributeSet.add(new LDAPAttribute("cn", new String[] { account }));
			if (usuario.getNom() != null)
				attributeSet.add(new LDAPAttribute("givenname", usuario.getNom()));
			if (usuario.getCodi() != null)
			attributeSet.add(new LDAPAttribute("uid", usuario.getCodi()));
			attributeSet.add(new LDAPAttribute("sn", usuario.getPrimerLlinatge() + 
					( usuario.getSegonLlinatge()!=null ? " " + usuario.getSegonLlinatge() : "") ));
			if (usuario.getNomCurt() != null) {
				attributeSet.add(new LDAPAttribute("mail", textify(
						usuario.getNomCurt(), usuario.getDominiCorreu())));
			} else { // Si no té nom curt afegim el mail addicional.. si el té
				// Si no té cap informació... no posem res (abans no se posava l'atribut)
				try {
					DadaUsuari mailContacteDadesAddicionals = getServer().getUserData(usuario.getId(),
							"EMAIL");
					// Si no existe no añadimos el atributo
					if (mailContacteDadesAddicionals!=null && !"".equals(mailContacteDadesAddicionals.getValorDada().trim()) ) {
						attributeSet.add(new LDAPAttribute("mail", mailContacteDadesAddicionals.getValorDada().trim()));
					}
				} catch (Throwable th) {
					// Si dóna error, no posem res (abans si no tenia ShortName no se posava res)
				}
				
			}
//			if (usuario.getNIF() != null)
//				attributeSet.add(new LDAPAttribute("nif", usuario.getNIF()));
			// Grup primari de l'usuari
			//log.info ("addUsuario('"+ui.User+"'). Añadiendo grupo primario de usuario = ["+"departmentNumber="+ ui.PrimaryGroup+"]",null,null);
			attributeSet.add(new LDAPAttribute("departmentNumber", usuario.getCodiGrupPrimari()));
			
			String dn = "cn=" + usuario.getCodi() + "," + usersContext;
			// Añadimos los Roles necesarios:
			if (useMemberOf)
			{
				HashSet<String> memberOf = new HashSet<String>(); // Es poden repetir (només ho posem per nom del rol)
				for (RolGrant rg: userRoles) {
					memberOf.add("cn=" + rg.getRolName()+ "," + rolesContext);
				}
	
				// Afegim el "rol" de tipus d'usuari
				if (usuario.getTipusUsuari() != null)	
					memberOf.add(new String("cn=" + "usuari-tipus-" + usuario.getTipusUsuari() + "," + rolesContext));
				
				if (memberOf.size() > 0) {
					attributeSet.add(new LDAPAttribute("memberOf",(String[]) memberOf.toArray(new String[0])));
				}
			}
			
			// Usuari nou, li afegim la seua contrasenya (if exists)
			Password pass = getServer().getAccountPassword(account, getDispatcher().getCodi());
			if (pass!=null) {
				String hash = getHashPassword(pass);
				LDAPAttribute atributo = new LDAPAttribute("userPassword", hash);
				attributeSet.add(atributo);
				log.info("Usuari nou {}: creant nova entrada amb contrasenya", usuario != null ? usuario.getCodi() : "", null);
			}

			
			//
			LDAPEntry newEntry = new LDAPEntry(dn, attributeSet);
			getConnection().add(newEntry);
		} catch (Exception e) {
			String msg = "addUsuario ('" + usuario.getCodi()
					+ "'). Error al crear usuario. ["+ e.getMessage()+"]";
			log.warn(msg, e);
			throw new InternalErrorException(msg,e);
		}
	}

	/**
	 * Modifica los datos de la entrada de un usuario del directorio LDAP
	 * 
	 * @param Entry
	 *            Entrada LDAP del usuario a modificar
	 * @param usuario
	 *            Informacion del usuario a modificar en el seycon
	 * @throws InternalErrorException
	 *             Error al modificar el usuario al directorio LDAP
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	private void modificarUsuario(LDAPEntry Entry, String account, Usuari usuario, Collection<RolGrant> collection)
			throws InternalErrorException {
		try {
			ArrayList modList = new ArrayList();
			if (Entry != null) {
				String dn = Entry.getDN();
				LDAPAttribute atributo;
				if (usuario.getNom() != null)
				{
					atributo = new LDAPAttribute("givenname", usuario.getNom());
					modList.add(new LDAPModification(LDAPModification.REPLACE,
							atributo));
				}
				atributo = new LDAPAttribute("sn", usuario.getPrimerLlinatge() + 
						( usuario.getSegonLlinatge()!=null ? " " + usuario.getSegonLlinatge() : "") );
				modList.add(new LDAPModification(LDAPModification.REPLACE,
						atributo));
//				if (usuario.getNIF() != null) {
//					atributo = new LDAPAttribute("nif", usuario.getNIF());
//					modList.add(new LDAPModification(LDAPModification.REPLACE,
//							atributo));
//				}
				// Modificamos la dirección de correo
				if (usuario.getNomCurt() != null && usuario.getNomCurt().trim().length() > 0) {
					atributo = new LDAPAttribute("mail", textify(usuario.getNomCurt(), usuario.getDominiCorreu()));
					modList.add(new LDAPModification(
							Entry.getAttribute("mail") == null ? LDAPModification.ADD: LDAPModification.REPLACE, 
									atributo));					
				} else { // Si no té nom curt afegim el mail addicional.. si el té
					// Si no té cap informació... no posem res (abans no se posava l'atribut)
					try {
						DadaUsuari mailContacteDadesAddicionals = getServer().getUserData(usuario.getId(),
								"EMAIL");
						// Si no existe no añadimos el atributo
						if (mailContacteDadesAddicionals!=null && mailContacteDadesAddicionals.getValorDada() != null &&
								!"".equals(mailContacteDadesAddicionals.getValorDada().trim()) ) {
							atributo = new LDAPAttribute("mail", mailContacteDadesAddicionals.getValorDada().trim());
							modList.add(new LDAPModification(
									Entry.getAttribute("mail") == null ? LDAPModification.ADD: LDAPModification.REPLACE, 
											atributo));
						}
					} catch (Throwable th) {
						// Si dóna error, no posem res 
					}
				}				
				
				// Añadimos los Roles necesarios:
				if (useMemberOf)
				{
					HashSet<String> memberOf = new HashSet<String>(); // Es poden repetir (només ho posem per nom del rol)
					for (RolGrant rg: collection) {
						memberOf.add(new String("cn=" + rg.getRolName() + "," + rolesContext));						
					}
	
					// Afegim el "rol" de tipus d'usuari
					if (usuario.getTipusUsuari() != null)
						memberOf.add(new String("cn=" + "usuari-tipus-" + usuario.getTipusUsuari() + "," + rolesContext));
				
					atributo = new LDAPAttribute("memberOf",(String[]) memberOf.toArray(new String[0]));
					modList.add(new LDAPModification(LDAPModification.REPLACE, atributo));
				}
				// Afegim el grup primari de l'usuari
				//log.info ("modificarUsuario('"+ui.User+"'). Cambiando grupo primario de usuario = ["+"departmentNumber="+ ui.PrimaryGroup+"]",null,null);
				if (usuario.getCodiGrupPrimari() != null)
					modList.add(new LDAPModification(LDAPModification.REPLACE,
						new LDAPAttribute("departmentNumber", usuario.getCodiGrupPrimari())));
				LDAPModification[] mods = new LDAPModification[modList.size()];
				mods = new LDAPModification[modList.size()];
				mods = (LDAPModification[]) modList.toArray(mods);
				getConnection().modify(dn, mods);
			}
		} catch (Exception e) {
			String msg = "modificarUsuario ('" + account + "'). Error al modificar usuario. ["+ e.getMessage()+"]";
			log.warn(msg,e);
			throw new InternalErrorException(msg,e);
		}
	}

	/**
	 * Generar una dirección de correo a partir de alias y dominio
	 * 
	 * @param alias
	 *            Nombre a figurar a la izquierda de la arroba
	 * @param domain
	 *            Subdominio opcional a figurar a la derecha de la arroba
	 * @return dirección válida de correo
	 */
	private String textify(String alias, String domain) {
		if (domain == null && alias.indexOf("@") >= 0)
			return alias;
		else 
			return alias + "@" + domain;
	}

	/**
	 * Actualiza el mail de un usuario en el directorio LDAP.
	 * 
	 * @param user
	 *            código de usuario
	 * @see LDAPAgent#UpdateUserAlias
	 */
	@SuppressWarnings("unchecked")
	public void updateUserAlias(String account, Usuari usuari) throws InternalErrorException  {
	}


	/** digest SHA-1 necesario para encriptar las contraseñas */
	{
		try {
			digest = MessageDigest.getInstance("SHA");
		} catch (java.security.NoSuchAlgorithmException e) {
			log.warn("Unable to use SHA encryption algorithm ",e);
			digest = null;
		}
	}
	// Codificar BASE 64
	static private String base64Array = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			+ "abcdefghijklmnopqrstuvwxyz" + "0123456789+/";

	public static String toBase64(byte source[]) {
		int i;
		int len = source.length;
		String result = "";
		for (i = 0; i < len; i += 3) {
			int c1, c2, c3;
			int index;
			c1 = source[i];
			if (i + 1 < len)
				c2 = (char) source[i + 1];
			else
				c2 = 0;
			if (i + 2 < len)
				c3 = (char) source[i + 2];
			else
				c3 = 0;
			index = (c1 & 0xfc) >> 2;
			result = result + base64Array.charAt(index);
			index = ((c1 & 0x03) << 4) | ((c2 & 0xf0) >> 4);
			result = result + base64Array.charAt(index);
			if (i + 1 >= len)
				result = result + "=";
			else {
				index = ((c2 & 0x0f) << 2) | ((c3 & 0xc0) >> 6);
				result = result + base64Array.charAt(index);
			}
			if (i + 2 >= len)
				result = result + '=';
			else {
				index = (c3 & 0x3f);
				result = result + base64Array.charAt(index);
			}
		}
		return result;
	}

	/**
	 * Actualiza los groupOfNames en el directorio LDAP Si el groupOfNames se
	 * queda sin members se elimina del directorio Inserta si es necesario una
	 * entrada de la clase groupOfNames en el directorio LDAP.<BR>
	 * 
	 * @throws InternalErrorException
	 *             Error en la propagación de datos al directorio LDAP.
	 */
	@SuppressWarnings("unchecked")
	public void updateRole(Rol rol) throws RemoteException,
			InternalErrorException {

		try {
			// Si estamos aquí, el rol se debe eliminar y volver a crear
			log.info("Actualizando rol: '" + rol.getNom() + "', bd=" + rol.getBaseDeDades(), null, null);			
			Collection<Account> users = getServer().getRoleActiveAccounts(rol.getId(), getDispatcher().getCodi());
					
			LDAPEntry roleEntry = buscarRole(rol.getNom());
			removeRole(rol.getNom(), rol.getBaseDeDades());
			
			if (users.size() < MAX_GROUP_MEMBERS) {
				LDAPAttributeSet attributeSet = new LDAPAttributeSet();
				attributeSet.add(new LDAPAttribute("objectclass", new String[] { "groupOfNames" }));
				attributeSet.add(new LDAPAttribute("cn", new String[] { rol.getNom() }));
				List myVector = new Vector();
				for (Account account: users) {
					myVector.add("cn=" + account.getName() + "," + usersContext);
				}
				if (myVector.isEmpty())
				{
					return;
				}
				attributeSet.add(new LDAPAttribute("member",
						(String[]) myVector.toArray(new String[0])));
				attributeSet.add(new LDAPAttribute("description", rol.getDescripcio()));
				String dn = "cn=" + rol.getNom() + "," + rolesContext;
				LDAPEntry newEntry = new LDAPEntry(dn, attributeSet);
				getConnection().add(newEntry);
			}
			else {
				log.info ("Detectado rol "+rol.getNom()+" con "+users.size()+" usuarios. Añadido y modificado en partes.",null,null);
				// Creamos el grupo (con MAX_GROUP_MEMBERS inicialmente)
				LDAPAttributeSet attributeSet = new LDAPAttributeSet();
				attributeSet.add(new LDAPAttribute("objectclass",
						new String[] { "groupOfNames" }));
				attributeSet.add(new LDAPAttribute("cn", new String[] { rol.getNom() }));
				List myVector = new Vector();
				Iterator<Account> it = users.iterator();
				for (int i = 0; it.hasNext() && i < MAX_GROUP_MEMBERS; i++) {
					Account account = it.next();
					myVector.add("cn=" + account.getName() + "," + usersContext);
				}
				attributeSet.add(new LDAPAttribute("member", (String[]) myVector
						.toArray(new String[0])));				
				
				attributeSet.add(new LDAPAttribute("description", rol.getDescripcio()));
				String dn = "cn=" + rol.getNom() + "," + rolesContext;
				LDAPEntry newEntry = new LDAPEntry(dn, attributeSet);
				
				// Creamos el grupo
				getConnection().add(newEntry); //Creamos el grupo
				// Y añadimos los miembros en bloques de MAX_GROUP_MEMBERS 
				while (it.hasNext()) {
					ArrayList modificacions = new ArrayList();
					for (int j = 0; it.hasNext() && j < MAX_GROUP_MEMBERS; j++) {
						Account account = it.next();
						modificacions.add(new LDAPModification(LDAPModification.ADD,
								new LDAPAttribute("member", "cn=" + account.getName() + ","
										+ usersContext)));
					}
					getConnection().modify(dn, (LDAPModification[]) modificacions.toArray(new LDAPModification[0]));
				}
			}

		} catch (Exception e) {
			String msg = "UpdateRole('" + rol.getNom() + "','" + rol.getBaseDeDades()
					+ "') Error al Actualizar roles. [" + e.getMessage() + "]";
			log.warn(msg,e);
			throw new InternalErrorException(msg,e);
		} 
	}

	/**
	 * Busca el groupOfNames en el directorio LDAP
	 * 
	 * @param role
	 *            groupOfNames a buscar.
	 * @return LDAPEntry[] array de groupOfNames.
	 * @throws InternalErrorException
	 *             Error al buscar Roles
	 */
	private LDAPEntry buscarRole(String role) throws InternalErrorException {
		try {
			log.info("Buscando rol: " + role,null,null);
			LDAPEntry Entry = new LDAPEntry();
			String searchBase = rolesContext;
			String searchFilter = "(&(objectclass=groupOfNames)(cn=" + role
					+ "))";
			int searchScope = LDAPConnection.SCOPE_ONE;
			LDAPSearchResults searchResults = getConnection().search(searchBase,
					searchScope, searchFilter, null, // return all attributes
					false); // return attrs and values
			if (searchResults.hasMore()) {
				log.info("Role encontrado: " + role + "\n -Longitud:"
						+ searchResults.getCount() + "\n -Resultado:"
						+ searchResults.toString(),null,null);
				Object object = searchResults.next();
				Entry = (LDAPEntry) object;
			} else {
				log.info("Role NO encontrado: " + role, null, null);
				Entry = null;
			}
			return (Entry);
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
				return null;
			} else {
				String msg = "buscarRole(" + role + "). Error al buscar rol. ["
						+ e.getMessage() + "]";
				log.warn(msg, e);
				throw new InternalErrorException(msg,e);
			}
		}
	}


	public void updateGroup(String groupName, Grup grup) throws RemoteException,
			InternalErrorException {
		try {
			// Si no existe lo creamos
			LDAPEntry grupEntry = buscarGrupo(groupName);
		} catch (Exception e) {
			String msg = "UpdateGroup('" + groupName
					+ "') Error al Actualizar grupo. [" + e.getMessage() + "]";
			log.warn(msg, e);
			throw new InternalErrorException(msg,e);
		}
	}
	
	/**
	 * Añade un nuevo inetOrgUnit en el directorio LDAP
	 * 
	 * @param gi
	 *            Información del inetOrgUnit a añadir
	 * @throws InternalErrorException
	 *             Error al añadir Grupo
	 */
	private void addGroup(String groupName, Grup gi) throws InternalErrorException {
		try {
			LDAPAttributeSet attributeSet = new LDAPAttributeSet();
			attributeSet.add(new LDAPAttribute("objectclass",
					new String[] { "inetOrgUnit" }));			
			attributeSet.add(new LDAPAttribute("cn", new String[] { groupName }));
			if (gi.getDescripcio()!=null) 
				attributeSet.add(new LDAPAttribute("description", gi.getDescripcio()));
			// Afegim un membre nul
			attributeSet.add(new LDAPAttribute("member", "cn=nul," + usersContext));
			String dn = "cn=" + groupName + "," + rolesContext;
			LDAPEntry newEntry = new LDAPEntry(dn, attributeSet);
			getConnection().add(newEntry);
		} catch (Exception e) {
			String msg = "addGroup ('" + groupName
					+ "'). Error al crear grupo. ["+ e.getMessage()+"]";
			log.warn(msg, e);
			throw new InternalErrorException(msg,e);
		}
	}
	
	@SuppressWarnings("unchecked")
	private void modificarGrupo(LDAPEntry Entry, Grup gi) throws InternalErrorException {
		try {
			ArrayList modList = new ArrayList();
			if (Entry != null) {
				String dn = Entry.getDN();
				
				// Descripción
				if (gi.getDescripcio()!=null) {
					LDAPAttribute atributo = new LDAPAttribute("description",gi.getDescripcio());
					if (Entry.getAttribute("description") == null) {
						modList.add(new LDAPModification(LDAPModification.ADD,
									atributo));
					} else {
						modList.add(new LDAPModification(LDAPModification.REPLACE,
									atributo));
					}					
				} else if (Entry.getAttribute("description") != null ) {
					modList.add(new LDAPModification(LDAPModification.DELETE,
							new LDAPAttribute("description")));
				}
				

				LDAPModification[] mods = new LDAPModification[modList.size()];
				mods = (LDAPModification[]) modList.toArray(mods);
				getConnection().modify(dn, mods);
			}
		} catch (Exception e) {
			String msg = "modificarGrupo ('" + gi.getCodi() + "'). Error al modificar grupo. ["+ e.getMessage()+"]";
			log.warn(msg,e);
			throw new InternalErrorException(msg,e);
		}
	}
	
	/**
	 * Busca el inetOrgUnit en el directorio LDAP
	 * 
	 * @param groupName
	 *            inetOrgUnit a buscar.
	 * @return LDAPEntry grupo buscado
	 * @throws InternalErrorException
	 *             Error al buscar Grupo
	 */
	private LDAPEntry buscarGrupo(String groupName) throws InternalErrorException {
		try {
			log.info("Buscando grupo: " + groupName,null,null);
			LDAPEntry Entry = new LDAPEntry();
			String searchBase = rolesContext;
			String searchFilter = "(&(objectclass=inetOrgUnit)(cn=" + groupName
					+ "))";
			int searchScope = LDAPConnection.SCOPE_ONE;
			LDAPSearchResults searchResults = getConnection().search(searchBase,
					searchScope, searchFilter, null, // return all attributes
					false); // return attrs and values
			if (searchResults.hasMore()) {
				log.info("Grupo encontrado: " + groupName,null,null);
				Object object = searchResults.next();
				Entry = (LDAPEntry) object;
			} else {
				log.info("Grupo NO encontrado: " + groupName, null, null);
				Entry = null;
			}
			return (Entry);
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
				return null;
			} else {
				String msg = "buscarGrup(" + groupName + "). Error al buscar grupo. ["
						+ e.getMessage() + "]";
				log.warn(msg, e);
				throw new InternalErrorException(msg,e);
			}
		}
	}

	/* (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.GroupMgr#removeGroup(java.lang.String)
	 */
	public void removeGroup(String groupName) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		LDAPEntry g = buscarGrupo(groupName);
		if (g != null)
		{
			try {
				getConnection().delete(g.getDN());
			} catch (LDAPException e) {
				throw new InternalErrorException("Error removing group "+g.getDN(), e);
			}
		}
			
	}

	/* (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.RoleMgr#removeRole(java.lang.String, java.lang.String)
	 */
	public void removeRole(String rolName, String dispatcher) {
		try {
			LDAPEntry r = buscarRole(rolName);
			if (r != null)
			{
				getConnection().delete(r.getDN());
			}
		} catch (Exception e) {
			throw new RuntimeException(new InternalErrorException("Error removing role "+rolName, e));
		}
	}

	/* (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.UserMgr#removeUser(java.lang.String)
	 */
	public void removeUser(String user) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			String deleteDN = "cn=" + user + "," + usersContext;
			getConnection().delete(deleteDN);
		} catch (Exception e) {
			if (e instanceof LDAPException &&
					((LDAPException)e).getResultCode() == LDAPException.NO_SUCH_OBJECT)
				return;

			String msg = "borrarUsuario ('"+user+"') Error al eliminar usuario. ["+ e.getMessage()+"]";
			log.warn(msg,e);
			throw new InternalErrorException(msg,e);
		}
	}

	/* (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.UserMgr#updateUser(java.lang.String, java.lang.String)
	 */
	public void updateUser(String name, String description) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		Usuari u = new Usuari();
		u.setCodi(null);
		u.setPrimerLlinatge(description);
		updateUser(name, u);
		
	}

	/* (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.UserMgr#validateUserPassword(java.lang.String, es.caib.seycon.ng.comu.Password)
	 */
	public boolean validateUserPassword(String arg0,
			es.caib.seycon.ng.comu.Password arg1) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		return false;
	}

}