module intel/isecl/lib/tpmprovider/v2

go 1.14

require (
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/tools v0.0.0-20191115173008-1c71899d35ca // indirect
	intel/isecl/lib/common/v2 v2.1.0

)

replace intel/isecl/lib/common/v2 => github.com/intel-secl/common/v2 v2.1.0
