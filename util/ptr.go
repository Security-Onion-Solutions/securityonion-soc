package util

func Ptr[T any](x T) *T {
	return &x
}

func Copy[T any](x *T) *T {
	if x == nil {
		return nil
	}

	return Ptr(*x)
}
