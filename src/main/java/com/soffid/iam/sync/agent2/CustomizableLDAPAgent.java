package com.soffid.iam.sync.agent2;

import java.rmi.RemoteException;

import com.novell.ldap.LDAPEntry;
import com.soffid.iam.api.SoffidObjectType;
import com.soffid.iam.sync.agent.CustomizableLDAPAgent2;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;

public class CustomizableLDAPAgent extends CustomizableLDAPAgent2 {

	public CustomizableLDAPAgent() throws RemoteException {
	}

	@Override
	public ExtensibleObject getNativeObject(es.caib.seycon.ng.comu.SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);
			for (ExtensibleObjectMapping map : objectMappings) {
				if (type.equals(map.getSoffidObject()) &&
						(! type.equals(SoffidObjectType.OBJECT_CUSTOM) ||
						 object1.equals(map.getSoffidCustomObject())))
				{
					ExtensibleObject sampleObject = objectTranslator.generateObject(sourceObject, map, true);
					if (sampleObject != null)
					{
						LDAPEntry entry = buscarUsuario(sampleObject);
						if (entry != null)
						{
							return parseEntry(entry, map);
							
						}
					}
				}
			}
			return null;
		} catch (Exception e) {
			throw new InternalErrorException("Error searching for LDAP object", e);
		}
	}

	@Override
	public ExtensibleObject getSoffidObject(es.caib.seycon.ng.comu.SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		ExtensibleObject src = getNativeObject(type, object1, object2);
		if (src == null)
			return null;
		else
		{
			ExtensibleObjects r = objectTranslator.parseInputObjects(src);
			for (ExtensibleObject eo: r.getObjects() )
			{
				return eo;
			}
			return null;
		}
	}

}
