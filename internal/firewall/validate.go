package firewall

import "regexp"

var namespacePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
