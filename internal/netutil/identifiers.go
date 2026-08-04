package netutil

import "regexp"

var (
	namespaceNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	interfaceNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	workerIDPattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
	resourcePrefixPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
)

func IsValidNamespaceName(name string) bool {
	return namespaceNamePattern.MatchString(name)
}

func IsValidInterfaceName(name string) bool {
	return interfaceNamePattern.MatchString(name)
}

func IsValidWorkerID(id string) bool {
	return workerIDPattern.MatchString(id)
}

func IsValidResourcePrefix(prefix string) bool {
	return resourcePrefixPattern.MatchString(prefix)
}
