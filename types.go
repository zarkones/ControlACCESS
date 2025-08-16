package access

type PermissionKey int

const (
	PERMISSION_NOT_SPECIFIED = PermissionKey(iota)
)

type Permission struct {
	Key       PermissionKey
	UserID    string
	Metadata  string
	CreatedAt int64
}
