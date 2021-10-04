package com.soffid.iam.sync.agent;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Map;

import com.novell.ldap.LDAPEntry;

import es.caib.seycon.ng.comu.ObjectMapping;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.Watchdog;
import es.caib.seycon.ng.sync.engine.extobj.ExtensibleObjectFinder;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;

public class LDAPObjectFinder implements ExtensibleObjectFinder {

	private CustomizableLDAPAgent agent;

	public LDAPObjectFinder(CustomizableLDAPAgent customizableLDAPAgent) {
		this.agent = customizableLDAPAgent;
	}

	public ExtensibleObject find(ExtensibleObject pattern) throws Exception {
		return agent.find(pattern);
	}

	public Collection<Map<String, Object>> invoke(String verb, String command, Map<String, Object> params)
			throws InternalErrorException {
		try {
			return agent.invoke(verb, command, params);
		} catch (RemoteException e) {
			throw new InternalErrorException("Error invoking command", e);
		}
	}

}
