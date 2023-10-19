package elastalert

type OneOrMore[T comparable] struct {
	Value  T
	Values []T
}

func (om *OneOrMore[T]) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var multi []T

	err := unmarshal(&multi)
	if err != nil {
		var single T

		err := unmarshal(&single)
		if err != nil {
			return err
		}

		om.Value = single
	} else {
		om.Values = multi
	}

	return nil
}

func (om OneOrMore[T]) MarshalYAML() (interface{}, error) {
	if om.Values != nil {
		return om.Values, nil
	}

	return om.Value, nil
}

func (om *OneOrMore[T]) HasValue() bool {
	var zero T
	return om != nil && (om.Values != nil || om.Value != zero)
}
