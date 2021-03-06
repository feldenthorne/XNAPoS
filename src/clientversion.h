#ifndef CLIENTVERSION_H
#define CLIENTVERSION_H

//
// client versioning
//

// These need to be macros, as version.cpp's and bitcoin-qt.rc's voodoo requires it
#define CLIENT_VERSION_MAJOR       2
#define CLIENT_VERSION_MINOR       3
#define CLIENT_VERSION_REVISION    1
#define CLIENT_VERSION_BUILD       0

// This is the client version name, used by the GUI and server for version reporting
#define CLIENT_VERSION_NAME "Thymine"

// Converts the parameter X to a string after macro replacement on X has been performed.
// Don't merge these into one macro!
#define STRINGIZE(X) DO_STRINGIZE(X)
#define DO_STRINGIZE(X) #X

// Copyright year
#define COPYRIGHT_YEAR  2015

#endif // CLIENTVERSION_H
