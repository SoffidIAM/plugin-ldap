package com.soffid.iam.sync.agent;

import java.rmi.RemoteException;
import java.util.Iterator;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;

import es.caib.seycon.ng.comu.ObjectMappingTrigger;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectTrigger;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.sync.engine.extobj.GrantExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;

public class CustomizableLDAPAgent2 extends
	CustomizableLDAPAgent {

	public CustomizableLDAPAgent2() throws RemoteException {
		super();
	}

	protected boolean runTrigger (SoffidObjectTrigger triggerType,
			ExtensibleObject soffidObject,
			ExtensibleObject adObject,
			LDAPEntry currentEntry) throws InternalErrorException
	{
		SoffidObjectType sot = SoffidObjectType.fromString(soffidObject.getObjectType());
		for ( ExtensibleObjectMapping eom : objectTranslator.getObjectsBySoffidType(sot))
		{
			if (adObject == null || adObject.getObjectType().equals(eom.getSystemObject()))
			{
				for ( ObjectMappingTrigger trigger: eom.getTriggers())
				{
					if (trigger.getTrigger().equals (triggerType))
					{
						ExtensibleObject eo = new ExtensibleObject();
						eo.setAttribute("source", soffidObject);
						eo.setAttribute("newObject", adObject);
						if ( currentEntry != null)
						{
							ExtensibleObject old = buildExtensibleObject(currentEntry);
							eo.setAttribute("oldObject", old);
						}
						if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
						{
							log.info("Trigger "+triggerType+" returned false");
							if (debugEnabled)
							{
								if (currentEntry != null)
									debugEntry("old object", currentEntry.getDN(), currentEntry.getAttributeSet());
								if (adObject != null)
									debugObject("new object", adObject, "  ");
							}
							return false;
						}
					}
				}
			}
		}
		return true;
		
	}

	@Override
	protected boolean preUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_UPDATE, soffidObject, adObject, currentEntry);
	}

	@Override
	protected boolean preInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_INSERT, soffidObject, adObject, null);
	}

	@Override
	protected boolean preDelete(ExtensibleObject soffidObject,
			LDAPEntry currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_DELETE, soffidObject, null, currentEntry);
	}

	@Override
	protected boolean prePassword(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_SET_PASSWORD, soffidObject, null, currentEntry);
	}

	@Override
	protected boolean postUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_UPDATE, soffidObject, adObject, currentEntry);
	}

	@Override
	protected boolean postInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_INSERT, soffidObject, adObject, currentEntry);
	}

	@Override
	protected boolean postDelete(ExtensibleObject soffidObject,
			LDAPEntry currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_DELETE, soffidObject,  null, currentEntry);
	}

	@Override
	protected boolean postPassword(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_SET_PASSWORD, soffidObject, adObject, currentEntry);
	}
}
