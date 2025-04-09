#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "pkcs11.h"
#include "P11Objects.h"
#include "config.h"
#include "Configuration.h"
#include "ObjectStore.h"
#include "SlotManager.h"
#include "OSPathSep.h"
#include "DBObject.h"
#include "Directory.h"
#include "DB.h"
#include "log.h"

#define FILL_ATTR(attr, typ, val, len) {(attr).type=(typ); (attr).pValue=(val); (attr).ulValueLen=len;}

CK_UTF8CHAR pPin[] = "1234";
CK_ULONG ulPinLen = strlen((const char *)pPin);
CK_UTF8CHAR pLabel[] = "token3";

static CK_RV extractObjectInformation(CK_ATTRIBUTE_PTR pTemplate,
				      CK_ULONG ulCount,
				      CK_OBJECT_CLASS &objClass,
				      CK_KEY_TYPE &keyType,
				      CK_CERTIFICATE_TYPE &certType,
				      CK_BBOOL &isOnToken,
				      CK_BBOOL &isPrivate,
				      bool bImplicit)
{
	bool bHasClass = false;
	bool bHasKeyType = false;
	bool bHasCertType = false;
	bool bHasPrivate = false;

	// Extract object information
	for (CK_ULONG i = 0; i < ulCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
				if (pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS))
				{
					objClass = *(CK_OBJECT_CLASS_PTR)pTemplate[i].pValue;
					bHasClass = true;
				}
				break;
			case CKA_KEY_TYPE:
				if (pTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE))
				{
					keyType = *(CK_KEY_TYPE*)pTemplate[i].pValue;
					bHasKeyType = true;
				}
				break;
			case CKA_CERTIFICATE_TYPE:
				if (pTemplate[i].ulValueLen == sizeof(CK_CERTIFICATE_TYPE))
				{
					certType = *(CK_CERTIFICATE_TYPE*)pTemplate[i].pValue;
					bHasCertType = true;
				}
				break;
			case CKA_TOKEN:
				if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
				{
					isOnToken = *(CK_BBOOL*)pTemplate[i].pValue;
				}
				break;
			case CKA_PRIVATE:
				if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
				{
					isPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
					bHasPrivate = true;
				}
				break;
			default:
				break;
		}
	}

	if (bImplicit)
	{
		return CKR_OK;
	}

	if (!bHasClass)
	{
		return CKR_TEMPLATE_INCOMPLETE;
	}

	bool bKeyTypeRequired = (objClass == CKO_PUBLIC_KEY || objClass == CKO_PRIVATE_KEY || objClass == CKO_SECRET_KEY);
	if (bKeyTypeRequired && !bHasKeyType)
	{
		 return CKR_TEMPLATE_INCOMPLETE;
	}

	if (objClass == CKO_CERTIFICATE)
	{
		if (!bHasCertType)
		{
			return CKR_TEMPLATE_INCOMPLETE;
		}
		if (!bHasPrivate)
		{
			// Change default value for certificates
			isPrivate = CK_FALSE;
		}
	}

	if (objClass == CKO_PUBLIC_KEY && !bHasPrivate)
	{
		// Change default value for public keys
		isPrivate = CK_FALSE;
	}

	return CKR_OK;
}

static CK_RV newP11Object(CK_OBJECT_CLASS objClass, CK_KEY_TYPE keyType, CK_CERTIFICATE_TYPE certType, P11Object **p11object)
{
	switch(objClass) {
		case CKO_DATA:
			*p11object = new P11DataObj();
			break;
		case CKO_CERTIFICATE:
			if (certType == CKC_X_509)
				*p11object = new P11X509CertificateObj();
			else if (certType == CKC_OPENPGP)
				*p11object = new P11OpenPGPPublicKeyObj();
			else {
				// printf("[bgk] ATTRIBUTE %s:%d:%s \n", __FILE__, __LINE__, __FUNCTION__);
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		case CKO_PUBLIC_KEY:
			if (keyType == CKK_RSA)
				*p11object = new P11RSAPublicKeyObj();
			else if (keyType == CKK_DSA)
				*p11object = new P11DSAPublicKeyObj();
			else if (keyType == CKK_EC)
				*p11object = new P11ECPublicKeyObj();
			else if (keyType == CKK_DH)
				*p11object = new P11DHPublicKeyObj();
			else if (keyType == CKK_GOSTR3410)
				*p11object = new P11GOSTPublicKeyObj();
			else if (keyType == CKK_EC_EDWARDS)
				*p11object = new P11EDPublicKeyObj();
			else {
				// printf("[bgk] ATTRIBUTE %s:%d:%s \n", __FILE__, __LINE__, __FUNCTION__);
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		case CKO_PRIVATE_KEY:
			// we need to know the type too
			if (keyType == CKK_RSA)
				*p11object = new P11RSAPrivateKeyObj();
			else if (keyType == CKK_DSA)
				*p11object = new P11DSAPrivateKeyObj();
			else if (keyType == CKK_EC)
				*p11object = new P11ECPrivateKeyObj();
			else if (keyType == CKK_DH)
				*p11object = new P11DHPrivateKeyObj();
			else if (keyType == CKK_GOSTR3410)
				*p11object = new P11GOSTPrivateKeyObj();
			else if (keyType == CKK_EC_EDWARDS)
				*p11object = new P11EDPrivateKeyObj();
			else {
				// printf("[bgk] ATTRIBUTE %s:%d:%s \n", __FILE__, __LINE__, __FUNCTION__);
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		case CKO_SECRET_KEY:
			if ((keyType == CKK_GENERIC_SECRET) ||
			    (keyType == CKK_MD5_HMAC) ||
			    (keyType == CKK_SHA_1_HMAC) ||
			    (keyType == CKK_SHA224_HMAC) ||
			    (keyType == CKK_SHA256_HMAC) ||
			    (keyType == CKK_SHA384_HMAC) ||
			    (keyType == CKK_SHA512_HMAC))
			{
				P11GenericSecretKeyObj* key = new P11GenericSecretKeyObj();
				*p11object = key;
				key->setKeyType(keyType);
			}
			else if (keyType == CKK_AES)
			{
				*p11object = new P11AESSecretKeyObj();
			}
			else if (keyType == CKK_SM4)
			{
				*p11object = new P11SM4SecretKeyObj();
			}
			else if ((keyType == CKK_DES) ||
				 (keyType == CKK_DES2) ||
				 (keyType == CKK_DES3))
			{
				P11DESSecretKeyObj* key = new P11DESSecretKeyObj();
				*p11object = key;
				key->setKeyType(keyType);
			}
			else if (keyType == CKK_GOST28147)
			{
				*p11object = new P11GOSTSecretKeyObj();
			}
			else {
				// printf("[bgk] ATTRIBUTE %s:%d:%s \n", __FILE__, __LINE__, __FUNCTION__);
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		case CKO_DOMAIN_PARAMETERS:
			if (keyType == CKK_DSA)
				*p11object = new P11DSADomainObj();
			else if (keyType == CKK_DH)
				*p11object = new P11DHDomainObj();
			else {
				// printf("[bgk] ATTRIBUTE %s:%d:%s \n", __FILE__, __LINE__, __FUNCTION__);
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		default:
			{
				// printf("[bgk] ATTRIBUTE %s:%d:%s \n", __FILE__, __LINE__, __FUNCTION__);
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
	}
	return CKR_OK;
}


CK_RV CreateObject(Slot* slot, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject, int op)
{
	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phObject == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the token
    Token* token = slot->getToken();
	if (token == NULL_PTR) return CKR_GENERAL_ERROR;

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass = CKO_DATA;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_BBOOL isOnToken = CK_TRUE;
	CK_BBOOL isPrivate = CK_FALSE;
	bool isImplicit = false;
	CK_RV rv = extractObjectInformation(pTemplate,ulCount,objClass,keyType,certType, isOnToken, isPrivate, isImplicit);
	if (rv != CKR_OK)
	{
		ERROR_MSG("Mandatory attribute not present in template");
		return rv;
	}

	// Change order of attributes
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE attribs[maxAttribs];
	CK_ATTRIBUTE saveAttribs[maxAttribs];
	CK_ULONG attribsCount = 0;
	CK_ULONG saveAttribsCount = 0;
	if (ulCount > maxAttribs)
	{
		return CKR_TEMPLATE_INCONSISTENT;
	}
	for (CK_ULONG i=0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CHECK_VALUE:
				saveAttribs[saveAttribsCount++] = pTemplate[i];
				break;
			default:
				attribs[attribsCount++] = pTemplate[i];
		}
	}
	for (CK_ULONG i=0; i < saveAttribsCount; i++)
	{
		attribs[attribsCount++] = saveAttribs[i];
	}

	P11Object* p11object = NULL;
	rv = newP11Object(objClass,keyType,certType,&p11object);
	if (rv != CKR_OK)
		return rv;

	// printf("[bgk] newP11Object ok %s:%d:%s \n", __FILE__, __LINE__, __FUNCTION__);
	// Create the object in session or on the token
	OSObject *object = object = (OSObject*) token->createObject();
	if (object == NULL || !p11object->init(object))
	{
		delete p11object;
		return CKR_GENERAL_ERROR;
	}

	rv = p11object->saveTemplate(token, isPrivate != CK_FALSE, attribs,attribsCount,op);
	delete p11object;
	if (rv != CKR_OK) {
		// printf("[bgk] saveTemplate rv = %ld, %s:%d:%s \n", rv, __FILE__, __LINE__, __FUNCTION__);
		return rv;
	}


	// printf("[bgk] saveTemplate ok %s:%d:%s \n", __FILE__, __LINE__, __FUNCTION__);

	if (op == OBJECT_OP_CREATE)
	{
		if (objClass == CKO_PUBLIC_KEY &&
		    (!object->startTransaction() ||
		    !object->setAttribute(CKA_LOCAL, false) ||
		    !object->commitTransaction()))
		{
			return CKR_GENERAL_ERROR;
		}

		if ((objClass == CKO_SECRET_KEY || objClass == CKO_PRIVATE_KEY) &&
		    (!object->startTransaction() ||
		    !object->setAttribute(CKA_LOCAL, false) ||
		    !object->setAttribute(CKA_ALWAYS_SENSITIVE, false) ||
		    !object->setAttribute(CKA_NEVER_EXTRACTABLE, false) ||
		    !object->commitTransaction()))
		{
			return CKR_GENERAL_ERROR;
		}
	}

	// *phObject = handleManager->addTokenObject(slot->getSlotID(), isPrivate != CK_FALSE, object);

	return CKR_OK;
}



int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    // Load the object store
    ObjectStore* objectStore = new ObjectStore(Configuration::i()->getString("directories.tokendir", DEFAULT_TOKENDIR),
    Configuration::i()->getInt("objectstore.umask", DEFAULT_UMASK));
    if (!objectStore->isValid()) {
        WARNING_MSG("Could not load the object store");
        delete objectStore;
        objectStore = NULL;
        return CKR_GENERAL_ERROR;
    }
    WARNING_MSG("Loaded the object store");

    // Load the slot manager
	SlotManager* slotManager = new SlotManager(objectStore);
    Slot* slot = slotManager->getSlot(1ul);
	if (slot == NULL) {
		return CKR_SLOT_ID_INVALID;
	}

	ByteString soPIN(pPin, ulPinLen);
    slot->initToken(soPIN, pLabel);

    // Create Data Objects
    CK_OBJECT_HANDLE data_obj;
    CK_ATTRIBUTE data_templ[20];
    CK_BYTE contents[] = "123456789abcdef";
    CK_OBJECT_CLASS clazz = CKO_DATA;
    CK_BBOOL _true = TRUE;
    CK_BBOOL _false = FALSE;
    FILL_ATTR(data_templ[0], CKA_CLASS, &clazz, sizeof(clazz));
    FILL_ATTR(data_templ[1], CKA_TOKEN, &_true, sizeof(_true));
    FILL_ATTR(data_templ[2], CKA_VALUE, contents, sizeof(contents));

    int n_data_attr	 = 3;
    FILL_ATTR(data_templ[n_data_attr], CKA_PRIVATE, &_false, sizeof(_false));
    n_data_attr++;

    char opt_object_label[] = "data3";
    FILL_ATTR(data_templ[n_data_attr], CKA_LABEL, opt_object_label, strlen(opt_object_label));
    n_data_attr++;

    CK_RV rv = CreateObject(slot, data_templ, n_data_attr, &data_obj, OBJECT_OP_CREATE);
    if (rv != CKR_OK) {
        printf("CreateObject failed rv = %ld", rv);
        return false;
    }

    printf("CreateObject success rv = %ld", rv);
    return true;
}