package com.soffid.iam.sync.agent2;

import java.io.IOException;
import java.rmi.RemoteException;

import com.novell.ldap.LDAPEntry;
import com.soffid.iam.api.CustomObject;
import com.soffid.iam.api.SoffidObjectType;
import com.soffid.iam.sync.agent.CustomizableLDAPAgent2;
import com.soffid.iam.sync.intf.CustomObjectMgr;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;

public class CustomizableLDAPAgent extends CustomizableLDAPAgent2 
	implements CustomObjectMgr
{
	
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

	public void updateCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		ExtensibleObject soffidObject = new es.caib.seycon.ng.sync.engine.extobj.CustomExtensibleObject(obj, getServer());
		ExtensibleObjects objects = objectTranslator.generateObjects(soffidObject);
		try {
			updateObjects(obj.getName(), objects, soffidObject);
		} catch (Exception e) {
			throw new InternalErrorException("Error updating LDAP object", e);
		}
	}

	public void removeCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		ExtensibleObject soffidObject = new es.caib.seycon.ng.sync.engine.extobj.CustomExtensibleObject(obj, getServer());
		ExtensibleObjects objects = objectTranslator.generateObjects(soffidObject);
		try {
			removeObjects(objects, soffidObject);
		} catch (Exception e) {
			throw new InternalErrorException("Error updating LDAP object", e);
		}
	}
}
