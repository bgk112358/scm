#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "OSPathSep.h"
#include "DBObject.h"
#include "Directory.h"
#include "DB.h"
#include "log.h"

// const char * const DBTOKEN_FILE = "sqlite3.db";
// const long long DBTOKEN_OBJECT_TOKENINFO = 1;

// DB::Connection *_connection;

// // Constructor for creating a new token.
// void DBToken(const std::string &baseDir, const std::string &tokenName , int umask/*, const ByteString &label, const ByteString &serial*/)
// {
//     _connection = nullptr;
// 	std::string tokenDir = baseDir + OS_PATHSEP + tokenName;
// 	std::string tokenPath = tokenDir + OS_PATHSEP + DBTOKEN_FILE;

//     std::cout << "[bgk] DBToken 1" << std::endl;
// 	// Refuse to open an already existing database.
// 	FILE *f = fopen(tokenPath.c_str(),"r");
// 	if (f)
// 	{
// 		fclose(f);
// 		ERROR_MSG("Refusing to overwrite and existing database at \"%s\"", tokenPath.c_str());
// 		return;
// 	}

//     std::cout << "[bgk] DBToken 2" << std::endl;
// 	// First create the directory for the token, we expect basePath to already exist
// 	if (::mkdir(tokenDir.c_str(), S_IFDIR | ((S_IRWXU | S_IRWXG | S_IRWXO) & ~umask)))
// 	{
// 		// Allow the directory to exists already.
// 		if (errno != EEXIST)
// 		{
// 			ERROR_MSG("Unable to create directory \"%s\"", tokenDir.c_str());
// 			return;
// 		}
// 	}

//     std::cout << "[bgk] DBToken 3" << std::endl;
// 	// Create
// 	_connection = DB::Connection::Create(tokenDir, DBTOKEN_FILE, umask);
// 	if (_connection == NULL)
// 	{
// 		ERROR_MSG("Failed to create a database connection for \"%s\"", tokenPath.c_str());
// 		return;
// 	}

//     std::cout << "[bgk] DBToken 4" << std::endl;
// 	if (!_connection->connect())
// 	{
// 		delete _connection;
// 		_connection = NULL;

// 		ERROR_MSG("Failed to connect to the database at \"%s\"", tokenPath.c_str());

// 		// Now remove the token directory
// 		if (remove(tokenDir.c_str()))
// 		{
// 			ERROR_MSG("Failed to remove the token directory \"%s\"", tokenDir.c_str());
// 		}

// 		return;
// 	}

//     std::cout << "[bgk] DBToken 5" << std::endl;
// 	// Create a DBObject for the established connection to the database.
// 	DBObject tokenObject(_connection);

// 	// First create the tables that support storage of object attributes and then insert the object containing
// 	// the token info into the database.
// 	if (!tokenObject.createTables() || !tokenObject.insert() || tokenObject.objectId()!=DBTOKEN_OBJECT_TOKENINFO)
// 	{
// 		tokenObject.dropConnection();

// 		_connection->close();
// 		delete _connection;
// 		_connection = NULL;

// 		ERROR_MSG("Failed to create tables for storing objects in database at \"%s\"", tokenPath.c_str());
// 		return;
// 	}

//     std::cout << "[bgk] DBToken 6" << std::endl;
// 	// // Set the initial attributes
// 	// CK_ULONG flags =
// 	// 	CKF_RNG |
// 	// 	CKF_LOGIN_REQUIRED | // FIXME: check
// 	// 	CKF_RESTORE_KEY_NOT_NEEDED |
// 	// 	CKF_TOKEN_INITIALIZED |
// 	// 	CKF_SO_PIN_LOCKED |
// 	// 	CKF_SO_PIN_TO_BE_CHANGED;

// 	// OSAttribute tokenLabel(label);
// 	// OSAttribute tokenSerial(serial);
// 	// OSAttribute tokenFlags(flags);

// 	// if (!tokenObject.setAttribute(CKA_OS_TOKENLABEL, tokenLabel) ||
// 	// 	!tokenObject.setAttribute(CKA_OS_TOKENSERIAL, tokenSerial) ||
// 	// 	!tokenObject.setAttribute(CKA_OS_TOKENFLAGS, tokenFlags))
// 	// {
// 	// 	_connection->close();
// 	// 	delete _connection;
// 	// 	_connection = NULL;

// 	// 	// Now remove the token file
// 	// 	if (remove(tokenPath.c_str()))
// 	// 	{
// 	// 		ERROR_MSG("Failed to remove the token file at \"%s\"", tokenPath.c_str());
// 	// 	}

// 	// 	// Now remove the token directory
// 	// 	if (remove(tokenDir.c_str()))
// 	// 	{
// 	// 		ERROR_MSG("Failed to remove the token directory at \"%s\"", tokenDir.c_str());
// 	// 	}
// 	// 	return;
// 	// }

// 	// _tokenMutex = MutexFactory::i()->getMutex();
// 	// // Success!
// }

// void CreateToken(const std::string basePath, const std::string tokenDir, int umask/*, const ByteString &label, const ByteString &serial*/)
// {
//     Directory baseDir(basePath);

//     std::cout << "[bgk] CreateToken 1" << std::endl;
//     if (!baseDir.isValid())
//     {
//         return;
//     }

//     std::cout << "[bgk] CreateToken 2" << std::endl;
//     // Create the token directory
//     if (!baseDir.mkdir(tokenDir, umask))
//     {
//         return;
//     }

//     std::cout << "[bgk] CreateToken 3" << std::endl;
//     DBToken(basePath, tokenDir, umask);

//     DEBUG_MSG("Created new token %s", tokenDir.c_str());

//     return;
// }


// // Create a new object
// DBObject *CreateObject()
// {
// 	DBObject *newObject = new DBObject(_connection, nullptr);
// 	if (newObject == NULL)
// 	{
// 		ERROR_MSG("Failed to create an object: out of memory");
// 		return NULL;
// 	}

// 	// if (!newObject->startTransaction(DBObject::ReadWrite))
// 	// {
// 	// 	delete newObject;
// 	// 	ERROR_MSG("Unable to start a transaction in token database at \"%s\"", _connection->dbpath().c_str());
// 	// 	return NULL;
// 	// }

// 	if (!newObject->insert())
// 	{
// 		newObject->abortTransaction();
// 		delete newObject;
// 		ERROR_MSG("Unable to insert an object into token database at \"%s\"", _connection->dbpath().c_str());
// 		return NULL;
// 	}

// 	if (!newObject->isValid())
// 	{
// 		newObject->abortTransaction();
// 		delete newObject;
// 		ERROR_MSG("Object that was inserted in not valid");
// 		return NULL;
// 	}

// 	if (!newObject->commitTransaction())
// 	{
// 		newObject->abortTransaction();
// 		delete newObject;
// 		ERROR_MSG("Unable to commit a created object to token database at \"%s\"", _connection->dbpath().c_str());
// 		return NULL;
// 	}

// 	// // Now add the new object to the list of existing objects.
// 	// {
// 	// 	_allObjects[newObject->objectId()] = newObject;
// 	// }

// 	return newObject;
// }


int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    // (void)CreateToken(DEFAULT_TOKENDIR, "newToken", DEFAULT_UMASK);

    // DBObject *dbobj = CreateObject();

    return true;
}